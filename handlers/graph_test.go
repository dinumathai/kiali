package handlers

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"github.com/stretchr/testify/assert"

	"github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/mock"
	"github.com/swift-sunshine/swscore/config"
	"github.com/swift-sunshine/swscore/prometheus"
)

// Setup mock

type promAPIMock struct {
	mock.Mock
}

func (o *promAPIMock) Query(ctx context.Context, query string, ts time.Time) (model.Value, error) {
	args := o.Called(ctx, query, ts)
	return args.Get(0).(model.Value), args.Error(1)
}

func (o *promAPIMock) QueryRange(ctx context.Context, query string, r v1.Range) (model.Value, error) {
	args := o.Called(ctx, query, r)
	return args.Get(0).(model.Value), args.Error(1)
}

func (o *promAPIMock) LabelValues(ctx context.Context, label string) (model.LabelValues, error) {
	args := o.Called(ctx, label)
	return args.Get(0).(model.LabelValues), args.Error(1)
}

func (o *promAPIMock) Series(ctx context.Context, matches []string, startTime time.Time, endTime time.Time) ([]model.LabelSet, error) {
	args := o.Called(ctx, matches, startTime, endTime)
	return args.Get(0).([]model.LabelSet), args.Error(1)
}

func setupMocked() (*prometheus.Client, *promAPIMock, error) {
	config.Set(config.NewConfig())
	api := new(promAPIMock)
	client, err := prometheus.NewClient()
	if err != nil {
		return nil, nil, err
	}
	client.Inject(api)
	return client, api, nil
}

func mockQuery(api *promAPIMock, query string, ret *model.Vector) {
	api.On(
		"Query",
		mock.AnythingOfType("*context.emptyCtx"),
		query,
		mock.AnythingOfType("time.Time")).
		Return(*ret, nil)
	api.On(
		"Query",
		mock.AnythingOfType("*context.cancelCtx"),
		query,
		mock.AnythingOfType("time.Time")).
		Return(*ret, nil)
}

func TestNamespaceGraph(t *testing.T) {
	q0 := "sum(rate(istio_request_count{source_version=\"unknown\",destination_service=~\".*\\\\.istio-system\\\\..*\",response_code=~\"[2345][0-9][0-9]\"} [600s])) by (source_service)"
	q0m0 := model.Metric{
		"source_service": ""}
	q0m1 := model.Metric{
		"source_service": "ingress.istio-system.svc.cluster.local"}
	v0 := model.Vector{
		&model.Sample{
			Metric: q0m0,
			Value:  0},
		&model.Sample{
			Metric: q0m1,
			Value:  0}}

	q1 := "sum(rate(istio_request_count{source_service=\"ingress.istio-system.svc.cluster.local\",source_version=\"unknown\",response_code=~\"[2345][0-9][0-9]\"} [600s]) * 60) by (destination_service,destination_version,response_code)"
	q1m0 := model.Metric{
		"destination_service": "productpage.istio-system.svc.cluster.local",
		"destination_version": "v1",
		"response_code":       "200"}
	v1 := model.Vector{
		&model.Sample{
			Metric: q1m0,
			Value:  100}}

	q2 := "sum(rate(istio_request_count{source_service=\"\",source_version=\"unknown\",response_code=~\"[2345][0-9][0-9]\"} [600s]) * 60) by (destination_service,destination_version,response_code)"
	q2m0 := model.Metric{
		"destination_service": "productpage.istio-system.svc.cluster.local",
		"destination_version": "v1",
		"response_code":       "200"}
	v2 := model.Vector{
		&model.Sample{
			Metric: q2m0,
			Value:  50}}

	q3 := "sum(rate(istio_request_count{source_service=\"productpage.istio-system.svc.cluster.local\",source_version=\"v1\",response_code=~\"[2345][0-9][0-9]\"} [600s]) * 60) by (destination_service,destination_version,response_code)"
	q3m0 := model.Metric{
		"destination_service": "reviews.istio-system.svc.cluster.local",
		"destination_version": "v1",
		"response_code":       "200"}
	q3m1 := model.Metric{
		"destination_service": "reviews.istio-system.svc.cluster.local",
		"destination_version": "v2",
		"response_code":       "200"}
	q3m2 := model.Metric{
		"destination_service": "reviews.istio-system.svc.cluster.local",
		"destination_version": "v3",
		"response_code":       "200"}
	q3m3 := model.Metric{
		"destination_service": "details.istio-system.svc.cluster.local",
		"destination_version": "v1",
		"response_code":       "200"}
	q3m4 := model.Metric{
		"destination_service": "productpage.istio-system.svc.cluster.local",
		"destination_version": "v1",
		"response_code":       "200"}
	v3 := model.Vector{
		&model.Sample{
			Metric: q3m0,
			Value:  20},
		&model.Sample{
			Metric: q3m1,
			Value:  20},
		&model.Sample{
			Metric: q3m2,
			Value:  20},
		&model.Sample{
			Metric: q3m3,
			Value:  20},
		&model.Sample{
			Metric: q3m4,
			Value:  20}}

	q4 := "sum(rate(istio_request_count{source_service=\"reviews.istio-system.svc.cluster.local\",source_version=\"v1\",response_code=~\"[2345][0-9][0-9]\"} [600s]) * 60) by (destination_service,destination_version,response_code)"
	v4 := model.Vector{}

	q5 := "sum(rate(istio_request_count{source_service=\"reviews.istio-system.svc.cluster.local\",source_version=\"v2\",response_code=~\"[2345][0-9][0-9]\"} [600s]) * 60) by (destination_service,destination_version,response_code)"
	q5m0 := model.Metric{
		"destination_service": "ratings.istio-system.svc.cluster.local",
		"destination_version": "v1",
		"response_code":       "200"}
	q5m1 := model.Metric{
		"destination_service": "reviews.istio-system.svc.cluster.local",
		"destination_version": "v2",
		"response_code":       "200"}
	v5 := model.Vector{
		&model.Sample{
			Metric: q5m0,
			Value:  20},
		&model.Sample{
			Metric: q5m1,
			Value:  20}}

	q6 := "sum(rate(istio_request_count{source_service=\"reviews.istio-system.svc.cluster.local\",source_version=\"v3\",response_code=~\"[2345][0-9][0-9]\"} [600s]) * 60) by (destination_service,destination_version,response_code)"
	q6m0 := model.Metric{
		"destination_service": "ratings.istio-system.svc.cluster.local",
		"destination_version": "v1",
		"response_code":       "200"}
	q6m1 := model.Metric{
		"destination_service": "reviews.istio-system.svc.cluster.local",
		"destination_version": "v3",
		"response_code":       "200"}
	v6 := model.Vector{
		&model.Sample{
			Metric: q6m0,
			Value:  20},
		&model.Sample{
			Metric: q6m1,
			Value:  20}}

	q7 := "sum(rate(istio_request_count{source_service=\"details.istio-system.svc.cluster.local\",source_version=\"v1\",response_code=~\"[2345][0-9][0-9]\"} [600s]) * 60) by (destination_service,destination_version,response_code)"
	v7 := model.Vector{}

	q8 := "sum(rate(istio_request_count{source_service=\"ratings.istio-system.svc.cluster.local\",source_version=\"v1\",response_code=~\"[2345][0-9][0-9]\"} [600s]) * 60) by (destination_service,destination_version,response_code)"
	v8 := model.Vector{}

	client, api, err := setupMocked()
	if err != nil {
		t.Error(err)
		return
	}
	mockQuery(api, q0, &v0)
	mockQuery(api, q1, &v1)
	mockQuery(api, q2, &v2)
	mockQuery(api, q3, &v3)
	mockQuery(api, q4, &v4)
	mockQuery(api, q5, &v5)
	mockQuery(api, q6, &v6)
	mockQuery(api, q7, &v7)
	mockQuery(api, q8, &v8)

	var fut func(w http.ResponseWriter, r *http.Request, c *prometheus.Client)

	mr := mux.NewRouter()
	mr.HandleFunc("/api/namespaces/{namespace}/graphs", http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			fut(w, r, client)
		}))

	ts := httptest.NewServer(mr)
	defer ts.Close()

	fut = graphNamespace
	url := ts.URL + "/api/namespaces/istio-system/graphs"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	actual, _ := ioutil.ReadAll(resp.Body)
	expected, _ := ioutil.ReadFile("testdata/test_namespace_graph.expected")
	expected = expected[:len(expected)-1] // remove EOF byte

	assert.Equal(t, string(expected), string(actual))
	assert.Equal(t, 200, resp.StatusCode)
}

func TestServiceGraph(t *testing.T) {
	q0 := "sum(rate(istio_request_count{destination_service=~\"reviews\\\\.istio-system\\\\..*\",response_code=~\"[2345][0-9][0-9]\"} [600s])) by (source_service, source_version)"
	q0m0 := model.Metric{
		"source_service": "productpage.istio-system.svc.cluster.local",
		"source_version": "v1"}
	q0m1 := model.Metric{
		"source_service": "reviews.istio-system.svc.cluster.local",
		"source_version": "v2"}
	q0m2 := model.Metric{
		"source_service": "reviews.istio-system.svc.cluster.local",
		"source_version": "v3"}
	v0 := model.Vector{
		&model.Sample{
			Metric: q0m0,
			Value:  20},
		&model.Sample{
			Metric: q0m1,
			Value:  20},
		&model.Sample{
			Metric: q0m2,
			Value:  20}}

	q1 := "sum(rate(istio_request_count{source_service=\"productpage.istio-system.svc.cluster.local\",source_version=\"v1\",destination_service=~\"reviews\\\\.istio-system\\\\..*\",response_code=~\"[2345][0-9][0-9]\"} [600s]) * 60) by (destination_service,destination_version,response_code)"
	q1m0 := model.Metric{
		"destination_service": "reviews.istio-system.svc.cluster.local",
		"destination_version": "v1",
		"response_code":       "200"}
	q1m1 := model.Metric{
		"destination_service": "reviews.istio-system.svc.cluster.local",
		"destination_version": "v2",
		"response_code":       "200"}
	q1m2 := model.Metric{
		"destination_service": "reviews.istio-system.svc.cluster.local",
		"destination_version": "v3",
		"response_code":       "200"}
	v1 := model.Vector{
		&model.Sample{
			Metric: q1m0,
			Value:  20},
		&model.Sample{
			Metric: q1m1,
			Value:  20},
		&model.Sample{
			Metric: q1m2,
			Value:  20}}

	q2 := "sum(rate(istio_request_count{source_service=\"reviews.istio-system.svc.cluster.local\",source_version=\"v1\",destination_service=~\".*\\\\.istio-system\\\\..*\",response_code=~\"[2345][0-9][0-9]\"} [600s]) * 60) by (destination_service,destination_version,response_code)"
	v2 := model.Vector{}

	q3 := "sum(rate(istio_request_count{source_service=\"reviews.istio-system.svc.cluster.local\",source_version=\"v2\",destination_service=~\".*\\\\.istio-system\\\\..*\",response_code=~\"[2345][0-9][0-9]\"} [600s]) * 60) by (destination_service,destination_version,response_code)"
	q3m0 := model.Metric{
		"destination_service": "reviews.istio-system.svc.cluster.local",
		"destination_version": "v2",
		"response_code":       "200"}
	q3m1 := model.Metric{
		"destination_service": "ratings.istio-system.svc.cluster.local",
		"destination_version": "v1",
		"response_code":       "200"}
	v3 := model.Vector{
		&model.Sample{
			Metric: q3m0,
			Value:  20},
		&model.Sample{
			Metric: q3m1,
			Value:  20}}

	q4 := "sum(rate(istio_request_count{source_service=\"reviews.istio-system.svc.cluster.local\",source_version=\"v3\",destination_service=~\".*\\\\.istio-system\\\\..*\",response_code=~\"[2345][0-9][0-9]\"} [600s]) * 60) by (destination_service,destination_version,response_code)"
	q4m0 := model.Metric{
		"destination_service": "reviews.istio-system.svc.cluster.local",
		"destination_version": "v3",
		"response_code":       "200"}
	q4m1 := model.Metric{
		"destination_service": "ratings.istio-system.svc.cluster.local",
		"destination_version": "v1",
		"response_code":       "200"}
	v4 := model.Vector{
		&model.Sample{
			Metric: q4m0,
			Value:  20},
		&model.Sample{
			Metric: q4m1,
			Value:  20}}

	client, api, err := setupMocked()
	if err != nil {
		t.Error(err)
		return
	}
	mockQuery(api, q0, &v0)
	mockQuery(api, q1, &v1)
	mockQuery(api, q2, &v2)
	mockQuery(api, q3, &v3)
	mockQuery(api, q4, &v4)

	var fut func(w http.ResponseWriter, r *http.Request, c *prometheus.Client)

	mr := mux.NewRouter()
	mr.HandleFunc("/api/namespaces/{namespace}/services/{service}/graphs", http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			fut(w, r, client)
		}))

	ts := httptest.NewServer(mr)
	defer ts.Close()

	fut = graphService
	url := ts.URL + "/api/namespaces/istio-system/services/reviews/graphs"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	actual, _ := ioutil.ReadAll(resp.Body)
	expected, _ := ioutil.ReadFile("testdata/test_service_graph.expected")
	expected = expected[:len(expected)-1] // remove EOF byte

	assert.Equal(t, string(expected), string(actual))
	assert.Equal(t, 200, resp.StatusCode)
}