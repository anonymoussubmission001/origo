package spa

import (
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

// neuteredFileSystem is used to prevent directory listing of static assets
type spaFileSystem struct {
	fs http.FileSystem
}

// spa handler
func (fs *spaFileSystem) Open(path string) (http.File, error) {

	f, err := fs.fs.Open(path)
	if os.IsNotExist(err) {
		if path == "/" {
			return fs.fs.Open("index.html")
		} else {
			return f, os.ErrNotExist
		}
	}
	return f, err
}

// router attached with just the spa handler, no service logic required here and solved over transport layer
func AttachRoutes(router *mux.Router, assetDir string) http.Handler {
	fs := http.FileServer(&spaFileSystem{http.Dir(assetDir)})
	router.PathPrefix("/").Handler(fs)
	return router
}
