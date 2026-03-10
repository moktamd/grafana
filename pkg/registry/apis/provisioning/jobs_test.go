package provisioning

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"

	authlib "github.com/grafana/authlib/types"

	"github.com/grafana/grafana/apps/provisioning/pkg/apis/auth"
	provisioning "github.com/grafana/grafana/apps/provisioning/pkg/apis/provisioning/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/utils"
	"github.com/grafana/grafana/pkg/registry/apis/provisioning/resources"
)

func TestAuthorizeDeleteTargets(t *testing.T) {
	dashboardGVR := resources.DashboardResource
	folderGVR := resources.FolderResource

	repoCfg := &provisioning.Repository{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-repo",
			Namespace: "default",
		},
		Spec: provisioning.RepositorySpec{
			Sync: provisioning.SyncOptions{
				Target: provisioning.SyncTargetTypeFolder,
			},
		},
	}

	forbidden := apierrors.NewForbidden(
		schema.GroupResource{Group: "test", Resource: "test"},
		"test",
		fmt.Errorf("forbidden"),
	)

	tests := []struct {
		name         string
		opts         *provisioning.DeleteJobOptions
		setupAccess  func(*auth.MockAccessChecker)
		setupClients func(*resources.MockClientFactory)
		wantErr      bool
		errContains  string
	}{
		{
			name: "empty targets succeeds",
			opts: &provisioning.DeleteJobOptions{},
			setupAccess: func(m *auth.MockAccessChecker) {
				// no calls expected
			},
		},
		{
			name: "authorized file path",
			opts: &provisioning.DeleteJobOptions{
				Paths: []string{"team-a/dashboard.json"},
			},
			setupAccess: func(m *auth.MockAccessChecker) {
				m.EXPECT().Check(mock.Anything, mock.MatchedBy(func(req authlib.CheckRequest) bool {
					return req.Group == dashboardGVR.Group && req.Resource == dashboardGVR.Resource && req.Verb == utils.VerbDelete
				}), mock.AnythingOfType("string")).Return(nil)
			},
		},
		{
			name: "unauthorized file path returns error",
			opts: &provisioning.DeleteJobOptions{
				Paths: []string{"restricted/dashboard.json"},
			},
			setupAccess: func(m *auth.MockAccessChecker) {
				m.EXPECT().Check(mock.Anything, mock.Anything, mock.Anything).Return(forbidden)
			},
			wantErr:     true,
			errContains: "authorize delete file",
		},
		{
			name: "authorized directory path",
			opts: &provisioning.DeleteJobOptions{
				Paths: []string{"team-a/"},
			},
			setupAccess: func(m *auth.MockAccessChecker) {
				m.EXPECT().Check(mock.Anything, mock.MatchedBy(func(req authlib.CheckRequest) bool {
					return req.Group == folderGVR.Group && req.Resource == folderGVR.Resource && req.Verb == utils.VerbDelete
				}), mock.AnythingOfType("string")).Return(nil)
			},
		},
		{
			name: "unauthorized directory path returns error",
			opts: &provisioning.DeleteJobOptions{
				Paths: []string{"restricted/"},
			},
			setupAccess: func(m *auth.MockAccessChecker) {
				m.EXPECT().Check(mock.Anything, mock.Anything, mock.Anything).Return(forbidden)
			},
			wantErr:     true,
			errContains: "authorize delete folder",
		},
		{
			name: "deduplicates checks for same folder",
			opts: &provisioning.DeleteJobOptions{
				Paths: []string{
					"team-a/dash1.json",
					"team-a/dash2.json",
					"team-a/dash3.json",
				},
			},
			setupAccess: func(m *auth.MockAccessChecker) {
				// Only one call expected despite three files in the same folder
				m.EXPECT().Check(mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
			},
		},
		{
			name: "checks different folders separately",
			opts: &provisioning.DeleteJobOptions{
				Paths: []string{
					"team-a/dash1.json",
					"team-b/dash2.json",
				},
			},
			setupAccess: func(m *auth.MockAccessChecker) {
				m.EXPECT().Check(mock.Anything, mock.Anything, mock.Anything).Return(nil).Times(2)
			},
		},
		{
			name: "root folder file path",
			opts: &provisioning.DeleteJobOptions{
				Paths: []string{"dashboard.json"},
			},
			setupAccess: func(m *auth.MockAccessChecker) {
				m.EXPECT().Check(mock.Anything, mock.Anything, repoCfg.Name).Return(nil)
			},
		},
		{
			name: "authorized ResourceRef",
			opts: &provisioning.DeleteJobOptions{
				Resources: []provisioning.ResourceRef{
					{Name: "my-dash", Kind: "Dashboard", Group: "dashboard.grafana.app"},
				},
			},
			setupAccess: func(m *auth.MockAccessChecker) {
				m.EXPECT().Check(mock.Anything, mock.MatchedBy(func(req authlib.CheckRequest) bool {
					return req.Group == dashboardGVR.Group && req.Resource == dashboardGVR.Resource && req.Verb == utils.VerbDelete
				}), "folder-abc").Return(nil)
			},
			setupClients: func(m *resources.MockClientFactory) {
				dynClient := &mockDynamic{}
				dynClient.On("Get", mock.Anything, "my-dash", metav1.GetOptions{}, []string(nil)).
					Return(makeUnstructured("my-dash", "folder-abc"), nil)

				clients := resources.NewMockResourceClients(t)
				clients.EXPECT().ForKind(mock.Anything, schema.GroupVersionKind{
					Group: "dashboard.grafana.app",
					Kind:  "Dashboard",
				}).Return(dynClient, dashboardGVR, nil)

				m.EXPECT().Clients(mock.Anything, "default").Return(clients, nil)
			},
		},
		{
			name: "unauthorized ResourceRef returns error",
			opts: &provisioning.DeleteJobOptions{
				Resources: []provisioning.ResourceRef{
					{Name: "my-dash", Kind: "Dashboard", Group: "dashboard.grafana.app"},
				},
			},
			setupAccess: func(m *auth.MockAccessChecker) {
				m.EXPECT().Check(mock.Anything, mock.Anything, mock.Anything).Return(forbidden)
			},
			setupClients: func(m *resources.MockClientFactory) {
				dynClient := &mockDynamic{}
				dynClient.On("Get", mock.Anything, "my-dash", metav1.GetOptions{}, []string(nil)).
					Return(makeUnstructured("my-dash", "folder-abc"), nil)

				clients := resources.NewMockResourceClients(t)
				clients.EXPECT().ForKind(mock.Anything, mock.Anything).Return(dynClient, dashboardGVR, nil)

				m.EXPECT().Clients(mock.Anything, "default").Return(clients, nil)
			},
			wantErr:     true,
			errContains: "authorize delete",
		},
		{
			name: "ResourceRef not found is skipped",
			opts: &provisioning.DeleteJobOptions{
				Resources: []provisioning.ResourceRef{
					{Name: "missing-dash", Kind: "Dashboard", Group: "dashboard.grafana.app"},
				},
			},
			setupAccess: func(m *auth.MockAccessChecker) {
				// no permission check expected for not-found resource
			},
			setupClients: func(m *resources.MockClientFactory) {
				notFound := apierrors.NewNotFound(schema.GroupResource{}, "missing-dash")
				dynClient := &mockDynamic{}
				dynClient.On("Get", mock.Anything, "missing-dash", metav1.GetOptions{}, []string(nil)).
					Return(nil, notFound)

				clients := resources.NewMockResourceClients(t)
				clients.EXPECT().ForKind(mock.Anything, mock.Anything).Return(dynClient, dashboardGVR, nil)

				m.EXPECT().Clients(mock.Anything, "default").Return(clients, nil)
			},
		},
		{
			name: "ResourceRef with empty folder uses root folder",
			opts: &provisioning.DeleteJobOptions{
				Resources: []provisioning.ResourceRef{
					{Name: "root-dash", Kind: "Dashboard", Group: "dashboard.grafana.app"},
				},
			},
			setupAccess: func(m *auth.MockAccessChecker) {
				m.EXPECT().Check(mock.Anything, mock.Anything, repoCfg.Name).Return(nil)
			},
			setupClients: func(m *resources.MockClientFactory) {
				dynClient := &mockDynamic{}
				dynClient.On("Get", mock.Anything, "root-dash", metav1.GetOptions{}, []string(nil)).
					Return(makeUnstructured("root-dash", ""), nil)

				clients := resources.NewMockResourceClients(t)
				clients.EXPECT().ForKind(mock.Anything, mock.Anything).Return(dynClient, dashboardGVR, nil)

				m.EXPECT().Clients(mock.Anything, "default").Return(clients, nil)
			},
		},
		{
			name: "mixed paths and ResourceRef",
			opts: &provisioning.DeleteJobOptions{
				Paths: []string{"team-a/dashboard.json"},
				Resources: []provisioning.ResourceRef{
					{Name: "my-dash", Kind: "Dashboard", Group: "dashboard.grafana.app"},
				},
			},
			setupAccess: func(m *auth.MockAccessChecker) {
				m.EXPECT().Check(mock.Anything, mock.Anything, mock.Anything).Return(nil).Times(2)
			},
			setupClients: func(m *resources.MockClientFactory) {
				dynClient := &mockDynamic{}
				dynClient.On("Get", mock.Anything, "my-dash", metav1.GetOptions{}, []string(nil)).
					Return(makeUnstructured("my-dash", "folder-xyz"), nil)

				clients := resources.NewMockResourceClients(t)
				clients.EXPECT().ForKind(mock.Anything, mock.Anything).Return(dynClient, dashboardGVR, nil)

				m.EXPECT().Clients(mock.Anything, "default").Return(clients, nil)
			},
		},
		{
			name: "fails fast on first unauthorized path",
			opts: &provisioning.DeleteJobOptions{
				Paths: []string{
					"team-a/dash1.json",
					"team-b/dash2.json",
				},
			},
			setupAccess: func(m *auth.MockAccessChecker) {
				// First call fails, second should never happen
				m.EXPECT().Check(mock.Anything, mock.Anything, mock.Anything).Return(forbidden).Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accessMock := auth.NewMockAccessChecker(t)
			clientsMock := resources.NewMockClientFactory(t)

			tt.setupAccess(accessMock)
			if tt.setupClients != nil {
				tt.setupClients(clientsMock)
			}

			c := &jobsConnector{
				access:  accessMock,
				clients: clientsMock,
			}

			err := c.authorizeDeleteTargets(t.Context(), repoCfg, tt.opts)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					require.ErrorContains(t, err, tt.errContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func makeUnstructured(name, folder string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "dashboard.grafana.app/v1",
			"kind":       "Dashboard",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": "default",
			},
		},
	}
	if folder != "" {
		obj.SetAnnotations(map[string]string{
			utils.AnnoKeyFolder: folder,
		})
	}
	return obj
}

// mockDynamic is a minimal mock of dynamic.ResourceInterface for testing.
type mockDynamic struct {
	mock.Mock
}

var _ dynamic.ResourceInterface = (*mockDynamic)(nil)

func (m *mockDynamic) Get(ctx context.Context, name string, options metav1.GetOptions, subresources ...string) (*unstructured.Unstructured, error) {
	args := m.Called(ctx, name, options, subresources)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*unstructured.Unstructured), args.Error(1)
}

func (m *mockDynamic) Create(ctx context.Context, obj *unstructured.Unstructured, options metav1.CreateOptions, subresources ...string) (*unstructured.Unstructured, error) {
	return nil, nil
}

func (m *mockDynamic) Update(ctx context.Context, obj *unstructured.Unstructured, options metav1.UpdateOptions, subresources ...string) (*unstructured.Unstructured, error) {
	return nil, nil
}

func (m *mockDynamic) UpdateStatus(ctx context.Context, obj *unstructured.Unstructured, options metav1.UpdateOptions) (*unstructured.Unstructured, error) {
	return nil, nil
}

func (m *mockDynamic) Delete(ctx context.Context, name string, options metav1.DeleteOptions, subresources ...string) error {
	return nil
}

func (m *mockDynamic) DeleteCollection(ctx context.Context, options metav1.DeleteOptions, listOptions metav1.ListOptions) error {
	return nil
}

func (m *mockDynamic) List(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	return nil, nil
}

func (m *mockDynamic) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return nil, nil
}

func (m *mockDynamic) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, options metav1.PatchOptions, subresources ...string) (*unstructured.Unstructured, error) {
	return nil, nil
}

func (m *mockDynamic) Apply(ctx context.Context, name string, obj *unstructured.Unstructured, options metav1.ApplyOptions, subresources ...string) (*unstructured.Unstructured, error) {
	return nil, nil
}

func (m *mockDynamic) ApplyStatus(ctx context.Context, name string, obj *unstructured.Unstructured, options metav1.ApplyOptions) (*unstructured.Unstructured, error) {
	return nil, nil
}
