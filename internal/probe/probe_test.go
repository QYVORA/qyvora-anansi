package probe

import (
	"net/http"
	"testing"

	"github.com/QYVORA/qyvora-anansi-cli/internal/output"
)

func TestDetectTech(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		body    []byte
		want    []string
	}{
		{
			name:    "cloudflare server",
			headers: http.Header{"Server": []string{"cloudflare"}},
			body:    nil,
			want:    []string{"Cloudflare"},
		},
		{
			name:    "nginx server",
			headers: http.Header{"Server": []string{"nginx/1.20.0"}},
			body:    nil,
			want:    []string{"Nginx"},
		},
		{
			name:    "wordpress body",
			headers: http.Header{},
			body:    []byte("/wp-content/themes/"),
			want:    []string{"WordPress"},
		},
		{
			name:    "php powered by",
			headers: http.Header{"X-Powered-By": []string{"PHP/8.0"}},
			body:    nil,
			want:    []string{"PHP"},
		},
		{
			name:    "asp.net with version header",
			headers: http.Header{"X-Aspnet-Version": []string{"4.0"}},
			body:    nil,
			want:    []string{"ASP.NET"},
		},
		{
			name:    "react body",
			headers: http.Header{},
			body:    []byte("data-reactroot=\"\""),
			want:    []string{"React"},
		},
		{
			name:    "next.js body",
			headers: http.Header{},
			body:    []byte("_next/static/chunks"),
			want:    []string{"Next.js"},
		},
		{
			name:    "no tech",
			headers: http.Header{},
			body:    []byte("plain page"),
			want:    nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectTech(tt.headers, tt.body)
			if len(got) != len(tt.want) {
				t.Fatalf("detectTech() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("detectTech()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestLiveOnly(t *testing.T) {
	results := []output.ProbeResult{
		{FQDN: "live.example.com", IsAlive: true, URL: "https://live.example.com"},
		{FQDN: "dead.example.com", IsAlive: false},
	}
	live := LiveOnly(results)
	if len(live) != 1 {
		t.Fatalf("expected 1 live host, got %d", len(live))
	}
	if live[0].FQDN != "live.example.com" {
		t.Fatalf("expected live.example.com, got %s", live[0].FQDN)
	}
}

func TestRunEmptyHosts(t *testing.T) {
	// Guard against panics/division-by-zero when no hosts survive discovery.
	results, err := Run(output.New("terminal", false), nil, 1, 0, []string{"80"}, 0, false)
	if err != nil {
		t.Fatalf("Run with empty hosts returned error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("Run with empty hosts returned %d results, want 0", len(results))
	}
}

func TestRunEmptyPorts(t *testing.T) {
	// A missing --ports value must not cause a nil map / slice panic.
	results, err := Run(output.New("terminal", false), []string{"example.com"}, 1, 2, nil, 0, false)
	if err != nil {
		t.Fatalf("Run with nil ports returned error: %v", err)
	}
	_ = results
}
