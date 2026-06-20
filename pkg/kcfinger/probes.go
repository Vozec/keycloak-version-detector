package kcfinger

// Probe describes a static theme asset that Keycloak serves under
// /resources/<resourceVersion>/<ServedPath>.
//
// ServedPath is what the SDK requests from a live target.
// RepoPath is where the same file lives in the keycloak source tree
// (under themes/src/main/resources/theme/keycloak/), used by the source
// builder to populate the database from GitHub. Empty when the asset is not
// in the source tree (NpmBuilt assets such as patternfly.min.css).
type Probe struct {
	ServedPath string
	RepoPath   string
	// Discriminator marks files whose hash changes meaningfully between
	// releases (high signal). Non-discriminators (images that rarely change)
	// still help confirm the stock theme and narrow major ranges.
	Discriminator bool
	// NpmBuilt assets are not committed to the keycloak source tree; they are
	// bundled from npm at build time. The source builder skips them; the dist
	// builder (`builddb dist`) populates them from release artifacts.
	NpmBuilt bool
	// Floor, when set, raises the detected version floor to this value if the
	// asset is served (200). Used for assets introduced at a known release.
	Floor string
}

// DefaultProbes is the set of stock-theme files we fingerprint.
var DefaultProbes = []Probe{
	// Source-tree assets (matched against the source-built DB).
	{ServedPath: "welcome/keycloak/css/welcome.css", RepoPath: "welcome/resources/css/welcome.css", Discriminator: true},
	{ServedPath: "login/keycloak/css/login.css", RepoPath: "login/resources/css/login.css", Discriminator: true},
	{ServedPath: "common/keycloak/lib/pficon/pficon.css", RepoPath: "common/resources/lib/pficon/pficon.css", Discriminator: true},
	{ServedPath: "welcome/keycloak/logo.svg", RepoPath: "welcome/resources/logo.svg"},
	{ServedPath: "welcome/keycloak/background.svg", RepoPath: "welcome/resources/background.svg"},
	{ServedPath: "login/keycloak/img/keycloak-bg.png", RepoPath: "login/resources/img/keycloak-bg.png"},
	{ServedPath: "login/keycloak/img/keycloak-logo.png", RepoPath: "login/resources/img/keycloak-logo.png"},
	{ServedPath: "login/keycloak/img/keycloak-logo-text.png", RepoPath: "login/resources/img/keycloak-logo-text.png"},
	{ServedPath: "common/keycloak/img/favicon.ico", RepoPath: "common/resources/img/favicon.ico"},
	{ServedPath: "login/keycloak/img/feedback-error-sign.png", RepoPath: "login/resources/img/feedback-error-sign.png"},
	{ServedPath: "login/keycloak/img/feedback-success-sign.png", RepoPath: "login/resources/img/feedback-success-sign.png"},
	{ServedPath: "login/keycloak/img/feedback-warning-sign.png", RepoPath: "login/resources/img/feedback-warning-sign.png"},

	// npm-built assets — absent from the source tree, populated by `builddb
	// dist` (which also hashes every other served file). PatternFly's bundled
	// version tracks the Keycloak release tightly, so its hash is a strong
	// discriminator; we also keep it here for its version Floor and so it is
	// probed even against a source-only DB.
	{ServedPath: "common/keycloak/node_modules/@patternfly-v5/patternfly/patternfly.min.css", NpmBuilt: true, Discriminator: true, Floor: "24.0.0"},
	{ServedPath: "common/keycloak/node_modules/@patternfly/patternfly/patternfly.min.css", NpmBuilt: true, Discriminator: true},
}

// SourceUniverse is every committed static file in the stock "keycloak" theme
// across Keycloak's history (served under .../keycloak/ with no theme-inheritance
// ambiguity). The source builder hashes all of these per version; both their
// CONTENT and mere PRESENCE discriminate (old welcome images and login feedback
// arrows were removed in redesigns, etc.). Detection then probes whichever ones
// the DB marks as discriminating.
var SourceUniverse = []string{
	// welcome theme
	"welcome/keycloak/css/welcome.css",
	"welcome/keycloak/logo.svg",
	"welcome/keycloak/background.svg",
	"welcome/keycloak/admin-console.png",
	"welcome/keycloak/alert.png",
	"welcome/keycloak/bg.png",
	"welcome/keycloak/bug.png",
	"welcome/keycloak/keycloak-project.png",
	"welcome/keycloak/keycloak_logo.png",
	"welcome/keycloak/logo.png",
	"welcome/keycloak/mail.png",
	"welcome/keycloak/user.png",
	// login theme
	"login/keycloak/css/login.css",
	"login/keycloak/img/feedback-error-sign.png",
	"login/keycloak/img/feedback-success-sign.png",
	"login/keycloak/img/feedback-warning-sign.png",
	"login/keycloak/img/feedback-error-arrow-down.png",
	"login/keycloak/img/feedback-success-arrow-down.png",
	"login/keycloak/img/feedback-warning-arrow-down.png",
	"login/keycloak/img/keycloak-bg.png",
	"login/keycloak/img/keycloak-logo.png",
	"login/keycloak/img/keycloak-logo-text.png",
	// common theme
	"common/keycloak/img/favicon.ico",
	"common/keycloak/lib/pficon/pficon.css",
}

// SoftSignal probes are fetched for presence/absence only (a version floor).
type SoftSignal struct {
	Path       string
	MinVersion string
	Label      string
}

var SoftSignals = []SoftSignal{
	{Path: "login/keycloak/js/passwordVisibility.js", MinVersion: "24.0.0", Label: "password-visibility toggle"},
}
