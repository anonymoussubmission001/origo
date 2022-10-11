package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	// "log"
	cmds "github.com/anonymoussubmission001/origo/commands"
)

func newVersionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version number of origo cmd toolkit.",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("*** proco ***: version 0.1")
		},
	}

	return cmd
}

func OrigoCommand() *cobra.Command {

	// create new cobra command
	cmd := &cobra.Command{
		Use:   "origo",
		Short: "\nWelcome,\n\nHERMES is a command-line tool to execute different stages of the origo codebase.\n",
	}

	// proco version command
	cmd.AddCommand(newVersionCommand())

	// proco server commands
	cmd.AddCommand(cmds.StartServerCommand())
	cmd.AddCommand(cmds.StopServerCommand())
	cmd.AddCommand(cmds.GetConfigServerCommand())
	cmd.AddCommand(cmds.AliveServerCommand())

	// proco proxy commands
	cmd.AddCommand(cmds.StartProxyCommand())
	cmd.AddCommand(cmds.StopProxyCommand())
	cmd.AddCommand(cmds.GetConfigProxyCommand())
	cmd.AddCommand(cmds.AliveProxyCommand())

	cmd.AddCommand(cmds.ProxyPostProcessCommand())
	cmd.AddCommand(cmds.ProxyVerifyCommand())

	// proco prover commands
	cmd.AddCommand(cmds.ProverRequestCommand())

	cmd.AddCommand(cmds.ProverCompileCommand())
	cmd.AddCommand(cmds.ProverProveCommand())

	cmd.AddCommand(cmds.ProverCredsListCommand())
	cmd.AddCommand(cmds.ProverCredsGetCommand())
	cmd.AddCommand(cmds.ProverCredsRefreshCommand())

	cmd.AddCommand(cmds.ProverConfigCommand())

	// transpiler
	cmd.AddCommand(cmds.PolicyTranspileCommand())
	cmd.AddCommand(cmds.PolicyGetCommand())
	cmd.AddCommand(cmds.PolicyListCommand())

	return cmd
}

func main() {

	// start command-line toolkit
	cmd := OrigoCommand()
	if err := cmd.Execute(); err != nil {
		os.Exit(0)
	}
}
