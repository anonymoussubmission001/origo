package commands

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"syscall"

	"github.com/spf13/cobra"
)

type ProcessID struct {
	Pid int
}

type LocalServerConfig struct {
	HostAddr      string
	HostPort      string
	PathCaCrt     string
	PathServerPem string
	PathServerKey string
	UrlPath       string
}

func StartServerCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server-start",
		Short: "starts local golang https server with defined configs.",
		RunE: func(cmd *cobra.Command, args []string) error {

			// define command
			oscmd := exec.Command("./server")
			oscmd.Dir = "server"

			// start server
			if err := oscmd.Start(); err != nil {
				log.Println("cmd.Start() error:", err)
				return err
			}

			fmt.Println("***: server started with process id:", oscmd.Process.Pid)

			// write pid into json file to maintain
			data := ProcessID{
				Pid: oscmd.Process.Pid,
			}
			file, err := json.MarshalIndent(data, "", " ")
			if err != nil {
				log.Println("json.MarshalIndent() error:", err)
				return err
			}
			err = ioutil.WriteFile("server/pid.json", file, 0644)
			if err != nil {
				log.Println("ioutil.WriteFile() error:", err)
				return err
			}

			fmt.Println("***: started https server successfully.")

			return nil
		},
	}

	return cmd
}

func StopServerCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server-stop",
		Short: "stops local golang https server.",
		RunE: func(cmd *cobra.Command, args []string) error {

			// read pid
			jsonFile, err := os.Open("server/pid.json")
			if err != nil {
				log.Println("os.Open() error", err)
				return err
			}
			defer jsonFile.Close()

			byteValue, _ := ioutil.ReadAll(jsonFile)
			var pid ProcessID
			json.Unmarshal(byteValue, &pid)

			// find and kill server process
			process, err := os.FindProcess(pid.Pid)
			if err != nil {
				log.Println("os.FindProcess() error:", err)
				return err
			}
			err = process.Kill()
			if err != nil {
				log.Println("process.Kill() error:", err)
				return err
			}

			fmt.Println("***: stopped https server successfully.")

			// check server processes with: ps -aux

			return nil
		},
	}

	return cmd
}

func GetConfigServerCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server-config",
		Short: "returns server policy.",
		Run: func(cmd *cobra.Command, args []string) {

			// read config file
			jsonFile, err := os.Open("server/config1.json")
			if err != nil {
				log.Println("os.Open() error", err)
			}
			defer jsonFile.Close()

			// parse json
			byteValue, _ := ioutil.ReadAll(jsonFile)
			var configJson LocalServerConfig
			json.Unmarshal(byteValue, &configJson)

			s, err := json.MarshalIndent(configJson, "", "\t")
			if err != nil {
				log.Println("json.MashalIndent() error:", err)
			}

			// print to console
			fmt.Print(string(s))
			fmt.Println()
		},
	}

	return cmd
}

func AliveServerCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server-alive",
		Short: "checks if the server process is running.",
		RunE: func(cmd *cobra.Command, args []string) error {

			// read pid
			jsonFile, err := os.Open("server/pid.json")
			if err != nil {
				log.Println("os.Open() error", err)
				return err
			}
			defer jsonFile.Close()

			byteValue, _ := ioutil.ReadAll(jsonFile)
			var pid ProcessID
			json.Unmarshal(byteValue, &pid)

			// check if server process alive
			process, err := os.FindProcess(pid.Pid)
			if err != nil {
				log.Println("os.FindProcess error:", err)
				return err
			}

			// check if process exited
			err = process.Signal(syscall.Signal(0))
			if err != nil {
				fmt.Println("***: false")
			} else {
				fmt.Println("***: true")
			}

			return nil
		},
	}

	return cmd
}
