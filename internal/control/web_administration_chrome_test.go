package control

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestWebChromeAdministrationSectionsFollowPrototypeNavigation(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for administration navigation acceptance")
	}
	server, _, _, _, _, _ := enrollmentAuthorityFixture(t)
	host := httptest.NewServer(server.AdminHandler())
	defer host.Close()
	debug := openCommandChrome(t, host.URL+"/ssot")
	waitChromeEvaluation(t, debug, `document.querySelector('[data-administration-section="controls"]')`)
	for _, section := range []string{"administrators", "certificates", "configuration", "controls"} {
		chromeDo(t, debug, `document.querySelector('.administration-sidebar a[href="/ssot?section=`+section+`"]').click();true`)
		waitChromeEvaluation(t, debug, `document.querySelector('[data-administration-section="`+section+`"]')`)
		if chromeDo(t, debug, `document.querySelectorAll('.administration-sidebar nav a').length===4&&document.querySelectorAll('[data-administration-section]').length===1&&document.querySelector('.administration-sidebar [aria-current=page]').href.endsWith('section=`+section+`')&&document.documentElement.scrollWidth<=innerWidth`) != true {
			t.Fatal("section duplicated content, lost the original sidebar or exceeded its viewport", section)
		}
	}
	chromeDo(t, debug, `history.back();true`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-administration-section="configuration"]')`)
	chromeDo(t, debug, `history.forward();true`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-administration-section="controls"]')`)
	response := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/settings", nil))
	if response.Code != http.StatusNotFound {
		t.Fatal("replaced Settings startup path is still active")
	}
}
