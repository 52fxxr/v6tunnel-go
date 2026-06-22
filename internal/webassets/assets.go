package webassets

import "embed"

//go:embed server_dashboard.html
var ServerDashboard string

//go:embed client_ui.html
var ClientUI string