package deploy

import (
	"fmt"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/capeprivacy/cli/config"
	"github.com/capeprivacy/cli/sdk"
	"github.com/capeprivacy/cli/ui/capeclient"
)

type (
	validateMsg   struct{}
	zipMsg        struct{}
	dialMsg       struct{}
	nonceMsg      struct{}
	attestMsg     struct{}
	encryptMsg    struct{}
	uploadMsg     struct{}
	idReturnedMsg string
	errorMsg      error
)

var emphasis = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F67AC7"))
var viewStyle = lipgloss.NewStyle().Padding(0, 2, 1, 3)

type status int

const (
	deployInit status = iota
	validateFn
	zipping
	dialing
	nonce
	attesting
	encrypting
	uploading
	success
	errored
	quitting
)

func NewProgram(c *config.Config, function string) *tea.Program {
	return tea.NewProgram(newModel(c, function))
}

type model struct {
	spinner    spinner.Model
	function   string
	cfg        *config.Config
	err        errorMsg
	client     *sdk.Client
	dh         *deployHandler
	status     status
	functionID string
}

func newModel(c *config.Config, function string) model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	return model{
		spinner:  s,
		function: function,
		cfg:      c,
		status:   deployInit,
		dh:       newDeployHandler(),
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(
		capeclient.NewClient(m.cfg),
		m.spinner.Tick,
	)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			m.status = quitting
			return m, tea.Quit
		}
	case capeclient.NewClientMsg:
		m.client = msg
		return m, handleDeployRequest(m)
	case validateMsg:
		m.status = validateFn
		return m, nil
	case zipMsg:
		m.status = zipping
		return m, nil
	case dialMsg:
		m.status = dialing
		return m, nil
	case nonceMsg:
		m.status = nonce
		return m, nil
	case attestMsg:
		m.status = attesting
		return m, nil
	case encryptMsg:
		m.status = encrypting
		return m, nil
	case uploadMsg:
		m.status = uploading
		return m, nil
	case idReturnedMsg:
		m.functionID = string(msg)
		m.status = success
		return m, tea.Quit
	case errorMsg:
		m.err = msg
		m.status = errored
		return m, tea.Quit

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m model) View() string {
	s := fmt.Sprintf("Deploying %s to Cape", emphasis.Render(m.function)) + "\n"

	switch m.status {
	case deployInit:
		// s += fmt.Sprintf("\t%s Connecting to a secure enclave", m.spinner.View())
		break
	case validateFn:
		s += fmt.Sprintf("\t%s Validating %s", m.spinner.View(), emphasis.Render(m.function))
	case zipping:
		s += fmt.Sprintf("\t%s Zipping %s", m.spinner.View(), emphasis.Render(m.function))
	case dialing:
		s += fmt.Sprintf("\t%s Connecting to a secure enclave", m.spinner.View())
	case nonce:
		s += fmt.Sprintf("\t%s Sending a nonce", m.spinner.View())
	case attesting:
		s += fmt.Sprintf("\t%s Attesting", m.spinner.View())
	case encrypting:
		s += fmt.Sprintf("\t%s Locally encrypting %s", m.spinner.View(), emphasis.Render(m.function))
	case uploading:
		s += fmt.Sprintf("\t%s Sending %s to Cape", m.spinner.View(), emphasis.Render(m.function))
	case success:
		s += fmt.Sprintf("Success! Function ID -> %s", emphasis.Render(m.functionID))
	case errored:
		s = fmt.Sprintf("%s Error uploading %s\n\t%s", emphasis.Render("✗"), emphasis.Render(m.function), m.err)
	case quitting:
		s = "\t Upload aborted, goodbye!"
	}

	return viewStyle.Render(s)
}

func handleDeployRequest(m model) tea.Cmd {
	go func() {
		if err := m.client.Deploy(m.dh, m.function); err != nil {
			m.dh.Error(err)
		}
	}()

	return tea.Batch(
		handleEvent(m.dh.validateFn, validateMsg{}),
		handleEvent(m.dh.zipping, zipMsg{}),
		handleEvent(m.dh.dialing, dialMsg{}),
		handleEvent(m.dh.nonce, nonceMsg{}),
		handleEvent(m.dh.attesting, attestMsg{}),
		handleEvent(m.dh.encrypting, encryptMsg{}),
		handleEvent(m.dh.uploading, uploadMsg{}),
		handleIDReturned(m.dh),
		handleError(m.dh),
	)
}

func handleError(dh *deployHandler) tea.Cmd {
	return func() tea.Msg {
		return <-dh.err
	}
}

func handleEvent(evt chan struct{}, msg tea.Msg) tea.Cmd {
	return func() tea.Msg {
		<-evt
		return msg
	}
}

func handleIDReturned(dh *deployHandler) tea.Cmd {
	return func() tea.Msg {
		id := <-dh.idReturned
		return idReturnedMsg(id)
	}
}
