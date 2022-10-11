package capeclient

import (
	"github.com/capeprivacy/cli/config"
	"github.com/capeprivacy/cli/sdk"
	tea "github.com/charmbracelet/bubbletea"
)

type NewClientMsg *sdk.Client

func NewClient(cfg *config.Config) tea.Cmd {
	return func() tea.Msg {
		client, err := sdk.NewClient(cfg)
		if err != nil {
			return err
		}

		return NewClientMsg(client)
	}
}
