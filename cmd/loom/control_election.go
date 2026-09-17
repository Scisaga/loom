package main

import (
	"context"
	"errors"
	"time"

	"loom/internal/controlplane"
)

const (
	controlHeartbeatInterval = 1500 * time.Millisecond
	controlElectionBase      = 5 * time.Second
	controlElectionStep      = 750 * time.Millisecond
	controlElectionPoll      = 250 * time.Millisecond
)

func (runtime *controlRuntime) markRaftContact() {
	runtime.lastRaftContact.Store(time.Now().UnixNano())
}

func (runtime *controlRuntime) electionTimeout() time.Duration {
	rank := 0
	for index, member := range runtime.config.ControlSet.Members {
		if member.MemberID == runtime.config.MemberID {
			rank = index
			break
		}
	}
	return controlElectionBase + time.Duration(rank)*controlElectionStep
}

func (runtime *controlRuntime) preVoteAllowed() bool {
	last := runtime.lastRaftContact.Load()
	return last == 0 || time.Since(time.Unix(0, last)) >= runtime.electionTimeout()
}

func (runtime *controlRuntime) startStableConsensusLoop(ctx context.Context) <-chan error {
	done := make(chan error, 1)
	go func() {
		done <- runtime.runStableConsensusLoop(ctx)
		close(done)
	}()
	return done
}

func (runtime *controlRuntime) runStableConsensusLoop(ctx context.Context) error {
	heartbeat := time.NewTicker(controlHeartbeatInterval)
	election := time.NewTicker(controlElectionPoll)
	defer heartbeat.Stop()
	defer election.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-heartbeat.C:
			leader := runtime.consensusLeader(true)
			if leader == nil {
				continue
			}
			heartbeatContext, cancel := context.WithTimeout(ctx, controlHeartbeatInterval)
			_, err := leader.BroadcastCommit(heartbeatContext)
			cancel()
			if err != nil && !leader.IsCurrent() {
				runtime.setConsensusLeader(nil, false)
				runtime.markRaftContact()
			}
		case <-election.C:
			if runtime.consensusLeader(true) != nil || !runtime.preVoteAllowed() {
				continue
			}
			campaignContext, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := runtime.campaignAndRecover(campaignContext)
			cancel()
			runtime.markRaftContact()
			if err != nil && !errors.Is(err, controlplane.ErrRaftCampaignNotLeader) &&
				!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				return err
			}
		}
	}
}
