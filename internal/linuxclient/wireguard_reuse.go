package linuxclient

func (transaction *wireGuardTransaction) execution() wireGuardExecution {
	result := wireGuardExecution{WireGuard: []wireGuardExecutionLink{}}
	if transaction != nil {
		for _, owned := range transaction.owned {
			if owned.alias != "" {
				result.WireGuard = append(result.WireGuard, owned.peerLinks()...)
			}
		}
	}
	return result
}
