// Package web embeds the single-page frontend.
package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static
var assets embed.FS

// Handler serves the frontend from the embedded static directory.
func Handler() http.Handler {
	sub, err := fs.Sub(assets, "static")
	if err != nil {
		panic(err) // static dir is embedded at build time
	}
	return http.FileServerFS(sub)
}
