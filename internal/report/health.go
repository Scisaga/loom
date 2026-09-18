package report

import "fmt"

func componentProblem(component ComponentStatus) string {
	if component.Error != "" {
		return fmt.Sprintf("组件 %s 无法核对:%s（期望 %s）", component.Name, component.Error, component.Expected)
	}
	return fmt.Sprintf("组件 %s 版本漂移:实际 %s，期望 %s", component.Name, component.Actual, component.Expected)
}

func agentHealthProblems(agent *AgentState) []string {
	if agent == nil {
		return nil
	}
	var problems []string
	for _, selection := range agent.Selections {
		health := selection.Health
		if health != nil && health.Candidates > 0 && health.RecentFailed == health.Candidates {
			problems = append(problems, fmt.Sprintf("Agent %s 的 %d 个候选近期全部失败",
				selection.Declaration, health.Candidates))
		}
	}
	return problems
}
