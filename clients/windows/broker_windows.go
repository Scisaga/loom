//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"loom/internal/clientcore"
	"loom/internal/clientenroll"
)

type brokerRequest struct {
	Operation  string                 `json:"operation"`
	Invite     *clientenroll.Invite   `json:"invite,omitempty"`
	Preference *clientcore.Preference `json:"preference,omitempty"`
	ProfileID  string                 `json:"profile_id,omitempty"`
	Name       string                 `json:"name,omitempty"`
}

// §13.5：界面只收到显示状态和已授权出口，不传送配置正文、文件路径、API 密码或私钥。
type brokerSnapshot struct {
	State             portableGUIState            `json:"state"`
	Joined            bool                        `json:"joined"`
	DeviceID          string                      `json:"device_id"`
	Detail            string                      `json:"detail"`
	Routes            []portableRouteOption       `json:"routes,omitempty"`
	RouteSelected     int                         `json:"route_selected"`
	RouteBusy         bool                        `json:"route_busy"`
	RouteDetail       string                      `json:"route_detail"`
	Paths             []windowsPathDisplay        `json:"paths,omitempty"`
	ProfilesReady     bool                        `json:"profiles_ready"`
	Profiles          []windowsProfileDisplay     `json:"profiles,omitempty"`
	SelectedProfile   string                      `json:"selected_profile,omitempty"`
	ProfileName       string                      `json:"profile_name,omitempty"`
	ActiveProfile     string                      `json:"active_profile,omitempty"`
	ActiveProfileName string                      `json:"active_profile_name,omitempty"`
	ProfileDraft      *windowsProfileDraftDisplay `json:"profile_draft,omitempty"`
}

type brokerResponse struct {
	Snapshot brokerSnapshot `json:"snapshot"`
	Error    string         `json:"error,omitempty"`
}

func decodeBrokerRequest(body []byte) (brokerRequest, error) {
	var req brokerRequest
	if len(body) == 0 || len(body) > 16<<10 || !utf8.Valid(body) {
		return req, errors.New("服务请求长度无效")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	// §13.5：encoding/json 忽略字段大小写；同一字段的不同拼写也不能覆盖操作或邀请。
	if err := rejectConnectionProfileDuplicateFields(decoder, 0); err != nil {
		return req, errors.New("服务请求字段重复或结构无效")
	}
	decoder = json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return req, errors.New("服务请求格式无效")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return req, errors.New("服务请求含多余数据")
	}
	if req.ProfileID != "" && !validConnectionProfileID(req.ProfileID) {
		return req, errors.New("连接配置标识无效")
	}
	if req.Name != "" && validateConnectionProfileName(req.Name) != nil {
		return req, errors.New("连接配置名称无效")
	}
	switch req.Operation {
	case "cancel_add_profile":
		if req.ProfileID != "" || req.Invite != nil || req.Preference != nil || req.Name != "" {
			return req, errors.New("关闭加入面板不接受附加参数")
		}
	case "join_profile":
		if req.ProfileID != "" || req.Preference != nil || (req.Invite != nil && clientenroll.ValidateInvite(*req.Invite) != nil) {
			return req, errors.New("新增连接配置的加入参数无效")
		}
	case "status", "connect", "disconnect", "delete", "select_profile":
		if req.Invite != nil || req.Preference != nil || req.Name != "" || (req.Operation == "status" && req.ProfileID != "") || (req.Operation == "select_profile" && req.ProfileID == "") {
			return req, errors.New("服务操作不接受附加参数")
		}
	case "join":
		if req.Invite == nil || req.Preference != nil || req.Name != "" || clientenroll.ValidateInvite(*req.Invite) != nil {
			return req, errors.New("加入二维码无效")
		}
	case "preference":
		if req.Invite != nil || req.Preference == nil || req.Name != "" {
			return req, errors.New("出口选择无效")
		}
	case "add_profile", "rename_profile":
		if req.Invite != nil || req.Preference != nil || (req.Operation == "add_profile" && req.ProfileID != "") ||
			(req.Operation == "rename_profile" && (req.ProfileID == "" || req.Name == "")) {
			return req, errors.New("连接配置操作参数无效")
		}
	default:
		return req, errors.New("未支持的服务操作")
	}
	return req, nil
}

func (app *portableGUI) brokerSnapshot() brokerSnapshot {
	s := app.snapshot()
	return brokerSnapshot{State: s.state, Joined: s.joined, DeviceID: s.deviceID, Detail: s.detail, Routes: s.routeOptions, RouteSelected: s.routeSelected,
		RouteBusy: s.routeBusy, RouteDetail: s.routeDetail, Paths: s.paths, ProfilesReady: s.profilesReady, Profiles: s.profiles,
		SelectedProfile: s.selectedProfile, ProfileName: s.profileName, ActiveProfile: s.activeProfile, ActiveProfileName: s.activeProfileName,
		ProfileDraft: cloneProfileDraft(s.profileDraft)}
}

func (app *portableGUI) handleBrokerRequest(req brokerRequest) error {
	if m := app.profileManager(); m != nil {
		if req.Operation == "status" {
			return nil
		}
		if req.ProfileID == "" && !profileDraftOperation(req.Operation) && req.Operation != "disconnect" {
			req.ProfileID = m.snapshot().selectedProfile
		}
		return m.dispatch(req)
	}
	if app.profileHost && req.Operation != "status" {
		return errors.New("连接配置尚未就绪；不能绕过配置索引执行操作")
	}
	s := app.snapshot()
	switch req.Operation {
	case "status":
		return nil
	case "join":
		if s.joined || (s.state != guiNeedsJoin && s.state != guiError) {
			return errors.New("当前状态不能导入二维码")
		}
		app.importJoinInvite(*req.Invite)
	case "connect":
		if !s.joined || (s.state != guiStopped && s.state != guiError) {
			return errors.New("当前状态不能连接")
		}
		app.startRuntime()
	case "disconnect":
		app.stopRuntime()
	case "preference":
		return app.setRoutePreference(*req.Preference)
	case "delete":
		app.mu.Lock()
		idle := app.runCancel == nil && app.joined && (app.state == guiStopped || app.state == guiError)
		if idle {
			app.state = guiLoading
		}
		app.mu.Unlock()
		if !idle {
			return errors.New("请先断开，再删除本机 Device")
		}
		if err := removeWindowsLocalDevice(app.root, editionInstalled); err != nil {
			app.update(guiError, true, s.deviceID, "删除本机 Device 失败")
			return errors.New("删除本机 Device 失败")
		}
		app.mu.Lock()
		app.state, app.joined, app.deviceID, app.detail = guiNeedsJoin, false, "", ""
		app.routeOptions, app.routeSelected, app.routeDetail = nil, -1, ""
		app.mu.Unlock()
	default:
		return errors.New("未支持的服务操作")
	}
	return nil
}

func serveBroker(ctx context.Context, pipe windows.Handle, app *portableGUI) error {
	for ctx.Err() == nil {
		_, err := pipeOperation(ctx, pipe, func(overlap *windows.Overlapped) error {
			return windows.ConnectNamedPipe(pipe, overlap)
		})
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		connectionCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		body, err := readPipeMessage(connectionCtx, pipe)
		if err == nil {
			request, decodeErr := decodeBrokerRequest(body)
			clear(body)
			if decodeErr == nil {
				decodeErr = app.handleBrokerRequest(request)
			}
			response := brokerResponse{Snapshot: app.brokerSnapshot()}
			if decodeErr != nil {
				response.Error = decodeErr.Error()
			}
			output, marshalErr := json.Marshal(response)
			if marshalErr == nil && writePipeMessage(connectionCtx, pipe, output) == nil {
				// §13.5：读完确认后再断开，避免 DisconnectNamedPipe 丢弃尚未读取的响应。
				var ack [1]byte
				_ = pipeBytes(connectionCtx, pipe, ack[:], false)
			}
		}
		cancel()
		_ = windows.DisconnectNamedPipe(pipe)
	}
	return nil
}

func prepareInstalledService() (func(context.Context) error, error) {
	root, err := installedStateRoot()
	if err != nil {
		return nil, err
	}
	if err := validateInstalledState(root); err != nil {
		return nil, err
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Loom`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return nil, errors.New("缺少安装记录；请通过 MSI 安装客户端")
	}
	operatorSID, _, err := key.GetStringValue("OperatorSID")
	key.Close()
	if err != nil {
		return nil, errors.New("缺少安装用户记录；请修复 MSI 安装")
	}
	pipe, err := createBrokerPipe(installedPipeName, operatorSID)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context) error {
		defer windows.CloseHandle(pipe)
		logFile, err := os.OpenFile(filepath.Join(root, "client.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer logFile.Close()
		previousLog := log.Writer()
		log.SetOutput(logFile)
		defer log.SetOutput(previousLog)
		appCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		app := &portableGUI{profileHost: true, edition: editionInstalled, root: root, ctx: appCtx, cancel: cancel, state: guiLoading, routeSelected: -1}
		app.workers.Add(1)
		go func() { defer app.workers.Done(); app.initialize() }()
		err = serveBroker(ctx, pipe, app)
		app.beginClose()
		app.workers.Wait()
		return err
	}, nil
}

func callInstalledBroker(ctx context.Context, request brokerRequest) (brokerResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var response brokerResponse
	pipe, err := connectBrokerPipe(ctx, installedPipeName)
	if err != nil {
		return response, err
	}
	defer windows.CloseHandle(pipe)
	// §13.5：先核对 SCM 的 PID，再发送任何一次性加入凭据。
	if err := verifyBrokerServer(pipe); err != nil {
		return response, errors.New("无法验证 Loom 后台服务身份；请修复安装")
	}
	body, err := json.Marshal(request)
	if err != nil {
		return response, err
	}
	defer clear(body)
	if err := writePipeMessage(ctx, pipe, body); err != nil {
		return response, err
	}
	output, err := readPipeMessage(ctx, pipe)
	if err != nil {
		return response, err
	}
	if err := json.Unmarshal(output, &response); err != nil {
		return response, errors.New("后台服务返回无效状态")
	}
	if err := pipeBytes(ctx, pipe, []byte{1}, true); err != nil {
		return response, err
	}
	return response, nil
}

func (app *portableGUI) pollInstalledBroker() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		app.exchangeInstalledBroker(brokerRequest{Operation: "status"})
		select {
		case <-app.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (app *portableGUI) exchangeInstalledBroker(request brokerRequest) {
	app.brokerMu.Lock()
	defer app.brokerMu.Unlock()
	response, err := callInstalledBroker(app.ctx, request)
	if err != nil {
		app.mu.Lock()
		app.paths = nil
		app.brokerProfileDraft = nil
		for i := range app.brokerProfiles {
			if app.brokerProfiles[i].ID == app.activeProfile {
				app.brokerProfiles[i].State = guiError
			}
		}
		app.activeProfile = ""
		app.activeProfileName = ""
		app.mu.Unlock()
		app.update(guiError, app.snapshot().joined, "", err.Error())
		return
	}
	s := response.Snapshot
	app.mu.Lock()
	app.state, app.joined, app.deviceID, app.detail = s.State, s.Joined, s.DeviceID, s.Detail
	app.routeOptions, app.routeSelected, app.routeBusy, app.routeDetail = s.Routes, s.RouteSelected, s.RouteBusy, s.RouteDetail
	app.paths = s.Paths
	app.brokerProfilesReady, app.brokerProfiles = s.ProfilesReady, s.Profiles
	app.brokerProfileDraft = cloneProfileDraft(s.ProfileDraft)
	app.selectedProfile, app.profileName, app.activeProfile, app.activeProfileName = s.SelectedProfile, s.ProfileName, s.ActiveProfile, s.ActiveProfileName
	if response.Error != "" {
		app.detail = response.Error
	}
	app.mu.Unlock()
	app.repaint()
}

func (app *portableGUI) installedCommand(request brokerRequest) {
	app.workers.Add(1)
	go func() { defer app.workers.Done(); app.exchangeInstalledBroker(request) }()
}
