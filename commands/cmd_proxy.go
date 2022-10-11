package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	v "github.com/anonymoussubmission001/origo/proxy/verifier"
)

type ProxyConfig struct {
	HostAddr                  string
	HostPort                  string
	StoragePath               string
	ProverSentRecordsFileName string
	ServerSentRecordsFileName string
}

func StartProxyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proxy-start",
		Short: "starts proxy with defined configs.",
		RunE: func(cmd *cobra.Command, args []string) error {

			// define command
			oscmd := exec.Command("./proxy")
			oscmd.Dir = "proxy/service"

			// start server
			if err := oscmd.Start(); err != nil {
				log.Println("cmd.Start() error:", err)
				return err
			}

			fmt.Println("***: proxy started with process id:", oscmd.Process.Pid)

			// write pid into json file to maintain
			data := ProcessID{
				Pid: oscmd.Process.Pid,
			}
			file, err := json.MarshalIndent(data, "", " ")
			if err != nil {
				log.Println("json.MarshalIndent() error:", err)
				return err
			}
			err = ioutil.WriteFile("proxy/service/pid.json", file, 0644)
			if err != nil {
				log.Println("ioutil.WriteFile() error:", err)
				return err
			}

			fmt.Println("***: started proxy successfully.")

			return nil
		},
	}

	return cmd
}

func StopProxyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proxy-stop",
		Short: "stops proxy.",
		RunE: func(cmd *cobra.Command, args []string) error {

			// read pid
			jsonFile, err := os.Open("proxy/service/pid.json")
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

			fmt.Println("***: stopped proxy successfully.")

			// check proxy process with: ps -aux

			return nil
		},
	}

	return cmd
}

func GetConfigProxyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proxy-config",
		Short: "returns proxy config.",
		Run: func(cmd *cobra.Command, args []string) {

			// read config file
			jsonFile, err := os.Open("proxy/service/config1.json")
			if err != nil {
				log.Println("os.Open() error", err)
			}
			defer jsonFile.Close()

			// parse json
			byteValue, _ := ioutil.ReadAll(jsonFile)
			var configJson ProxyConfig
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

func AliveProxyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proxy-alive",
		Short: "checks if the proxy process is running.",
		RunE: func(cmd *cobra.Command, args []string) error {

			// read pid
			jsonFile, err := os.Open("proxy/service/pid.json")
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

func ProxyPostProcessCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proxy-postprocess",
		Short: "prepares captured data to build public input of the zkp.",
		RunE: func(cmd *cobra.Command, args []string) error {

			// handle input args
			if len(args) < 1 {
				fmt.Println()
				return errors.New("\n  please provide policy filename without extension: origo proxy-postprocess <policy-filename>\n")
			}
			policyFileName := args[0]

			// start logger
			f, start, err := StartLogging("proxy-postprocess")
			if err != nil {
				log.Println("StartLogging error", err)
				return err
			}

			// post processing struct
			pp, err := v.NewPP(policyFileName)
			if err != nil {
				log.Println("v.NewPP() error:", err)
				return err
			}

			// run post process
			err = pp.PostProcess()
			if err != nil {
				log.Println("proxy.PostProcess() error:", err)
				return err
			}

			// logger reset
			logrus.SetOutput(f)

			// stop logger
			err = StopLogging("proxy-postprocessing", f, start)
			if err != nil {
				log.Println("StopLogging error", err)
				return err
			}

			fmt.Println("***: post-processing successfull, created PublicInput.json in proxy/service/local_storage/ folder.")

			return nil
		},
	}

	return cmd
}

func ProxyVerifyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proxy-verify",
		Short: "verifies a zkp proof.",
		RunE: func(cmd *cobra.Command, args []string) error {

			// start logger
			f, start, err := StartLogging("proxy-verify")
			if err != nil {
				log.Println("StartLogging error", err)
				return err
			}

			// load verifier, no configs required
			verifier, err := v.NewVerifier()
			if err != nil {
				log.Println("v.NewVerifier() error:", err)
				return err
			}

			// run proof verification
			err = verifier.Verify()
			if err != nil {
				log.Println("verifier.Verify() error:", err)
				return err
			}

			// stop logger
			err = StopLogging("proxy-verify", f, start)
			if err != nil {
				log.Println("StopLogging error", err)
				return err
			}

			return nil
		},
	}

	return cmd
}
