// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

func trustSectionMeta(current screen) (string, string) {
	switch current {
	case screenTrustKeysThresholds:
		return "Home › Trust › Keys & Thresholds", "Add root keys, remove policy keys, and update thresholds."
	case screenTrustHooks:
		return "Home › Trust › Hooks", "Add, update, and remove trust hooks."
	case screenTrustPropagation:
		return "Home › Trust › Propagation", "Manage propagation directives for trust metadata."
	case screenTrustGitHubApp:
		return "Home › Trust › GitHub App", "Configure trusted GitHub App keys and approvals."
	case screenTrustLifecycle:
		return "Home › Trust › Lifecycle", "Stage, sign, and apply trust changes from the TUI."
	case screenTrustRepoNetwork:
		return "Home › Trust › Repo/Network", "Manage controller, network, and repository settings."
	default:
		return "Home › Trust", ""
	}
}

func (m model) renderTrustSectionScreen(current screen) string {
	title, desc := trustSectionMeta(current)

	var b strings.Builder
	b.WriteString(titleStyle.Render("Coming next") + "\n\n")
	b.WriteString(desc + "\n\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(colorSubtext)).Render(
		"This submenu is in place so trust workflows can land in the TUI without growing the shared router.",
	))
	b.WriteString("\n\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(colorSubtext)).Render(
		"Press Esc to return to the Trust menu.",
	))

	return m.renderScreen(title, b.String(), renderActionHints(true))
}
