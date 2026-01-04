package utils

import (
	"github.com/sirupsen/logrus"
)

// Logger provides a logging utility using logrus
var Logger = logrus.New()

func init() {
	// Configure logger
	Logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	Logger.SetLevel(logrus.InfoLevel)
}
