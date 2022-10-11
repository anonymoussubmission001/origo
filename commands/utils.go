package commands

import (
	"os"
	"time"
	"github.com/sirupsen/logrus"
	"log"
)

// logging for evaluation
func StartLogging(commandName string) (*os.File, time.Time , error) {

	// open logfile
	f, err := os.OpenFile("commands/evaluation.log", os.O_APPEND | os.O_CREATE | os.O_RDWR, 0666)
	if err != nil {
		log.Println("os.OpenFile error:", err)
		return nil, time.Time{}, err
	}
	logrus.SetOutput(f)
	logrus.Warning("---- START "+commandName+" LOG ----.")
	start := time.Now()
	return f, start, nil
}

func StopLogging(commandName string, f *os.File, start time.Time) error {
	elapsed := time.Since(start)
	logrus.WithFields(logrus.Fields{
		"time": elapsed,
	}).Info(commandName+" command took.")
	logrus.Warning("---- STOP "+commandName+" LOG ----.")
	err := f.Close()
	return err
}

