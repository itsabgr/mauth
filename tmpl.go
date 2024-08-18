package mauth

import (
	"embed"
	_ "embed"
	"github.com/itsabgr/fak"
	"html/template"
	"io"
)

//go:embed assets/login.html
var templateFS embed.FS
var loginTemplate *template.Template

func init() {
	loginTemplate = fak.Must(template.ParseFS(templateFS, "assets/login.html"))
}

type LoginTemplateArgs struct {
	Authentication *Authentication
}

func RenderLoginTemplate(dst io.Writer, args LoginTemplateArgs) error {
	return loginTemplate.Execute(dst, &args)
}
