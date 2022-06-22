package pipeline

import "testing"

func TestPolicyRepo_getPolicies(t *testing.T) {
	type fields struct {
		PolicyDir string
		RepoURL   string
		RepoRef   string
	}
	type args struct {
		dest string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Gets Policies",
			fields: fields{
				PolicyDir: "policy",
				RepoURL:   "https://example.com/user/foo.git",
				RepoRef:   "main",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			CheckoutRepo = checkoutRepoStub
			p := &PolicyRepo{
				PolicyDir: tt.fields.PolicyDir,
				RepoURL:   tt.fields.RepoURL,
				RepoRef:   tt.fields.RepoRef,
			}
			if err := p.getPolicies(tt.args.dest); (err != nil) != tt.wantErr {
				t.Errorf("getPolicies() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPolicyRepo_getPolicyDir(t *testing.T) {
	type fields struct {
		PolicyDir string
		RepoURL   string
		RepoRef   string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Returns Policy Directory",
			fields: fields{
				PolicyDir: "policies",
				RepoURL:   "https://example.com/user/foo.git",
				RepoRef:   "mail",
			},
			want: "policies",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &PolicyRepo{
				PolicyDir: tt.fields.PolicyDir,
				RepoURL:   tt.fields.RepoURL,
				RepoRef:   tt.fields.RepoRef,
			}
			if got := p.getPolicyDir(); got != tt.want {
				t.Errorf("getPolicyDir() = %v, want %v", got, tt.want)
			}
		})
	}
}
