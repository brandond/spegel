package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	// DefaultRegisterer and DefaultGatherer are the implementations of the
	// prometheus Registerer and Gatherer interfaces that all metrics operations
	// will use. They are variables so that packages that embed this library can
	// replace them at runtime, instead of having to pass around specific
	// registries.
	DefaultRegisterer = prometheus.DefaultRegisterer
	DefaultGatherer   = prometheus.DefaultGatherer
)

var (
	MirrorRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "spegel_mirror_requests_total",
		Help: "Total number of mirror requests.",
	}, []string{"registry", "cache", "source"})
	AdvertisedImages = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "spegel_advertised_images",
		Help: "Number of images advertised to be available.",
	}, []string{"registry"})
	AdvertisedKeys = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "spegel_advertised_keys",
		Help: "Number of keys advertised to be available.",
	}, []string{"registry"})
)

func Register() {
	DefaultRegisterer.MustRegister(MirrorRequestsTotal)
	DefaultRegisterer.MustRegister(AdvertisedImages)
	DefaultRegisterer.MustRegister(AdvertisedKeys)
}
