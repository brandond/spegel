package state

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/xenitab/pkg/channels"

	"github.com/xenitab/spegel/pkg/metrics"
	"github.com/xenitab/spegel/pkg/oci"
	"github.com/xenitab/spegel/pkg/routing"
)

// TODO: Update metrics on subscribed events. This will require keeping state in memory to know about key count changes.
func Track(ctx context.Context, ociClient oci.Client, router routing.Router, resolveLatestTag bool) {
	log := logr.FromContextOrDiscard(ctx)
	for {
		err := track(ctx, ociClient, router, resolveLatestTag)
		if err == nil || errors.Is(err, context.Canceled) {
			log.V(5).Info("image state tracker stopped")
			return
		}
		log.Error(err, "restarting image state tracker due to error")
	}
}

func track(ctx context.Context, ociClient oci.Client, router routing.Router, resolveLatestTag bool) error {
	log := logr.FromContextOrDiscard(ctx)
	eventCh, errCh := ociClient.Subscribe(ctx)
	immediate := make(chan time.Time, 1)
	immediate <- time.Now()
	expirationTicker := time.NewTicker(routing.KeyTTL - time.Minute)
	defer expirationTicker.Stop()
	ticker := channels.Merge(immediate, expirationTicker.C)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker:
			log.Info("running scheduled image state update")
			if err := all(ctx, ociClient, router, resolveLatestTag); err != nil {
				return fmt.Errorf("received errors when updating all images: %w", err)
			}
		case img, ok := <-eventCh:
			if !ok {
				return errors.New("image event channel closed")
			}
			log.Info("received image event", "image", img)
			if _, err := update(ctx, ociClient, router, img, false, resolveLatestTag); err != nil {
				log.Error(err, "received error when updating image")
				continue
			}
		case err, ok := <-errCh:
			if !ok {
				return errors.New("image error channel closed")
			}
			log.Error(err, "event channel error")
			continue
		}
	}
}

func all(ctx context.Context, ociClient oci.Client, router routing.Router, resolveLatestTag bool) error {
	imgs, err := ociClient.ListImages(ctx)
	if err != nil {
		return err
	}
	metrics.AdvertisedImages.Reset()
	metrics.AdvertisedKeys.Reset()
	errs := []error{}
	targets := map[string]interface{}{}
	for _, img := range imgs {
		_, skipDigests := targets[img.Digest.String()]
		keyTotal, err := update(ctx, ociClient, router, img, skipDigests, resolveLatestTag)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		targets[img.Digest.String()] = nil
		metrics.AdvertisedImages.WithLabelValues(img.Registry).Add(1)
		metrics.AdvertisedKeys.WithLabelValues(img.Registry).Add(float64(keyTotal))
	}
	return errors.Join(errs...)
}

func update(ctx context.Context, ociClient oci.Client, router routing.Router, img oci.Image, skipDigests, resolveLatestTag bool) (int, error) {
	keys := []string{}
	if !(!resolveLatestTag && img.IsLatestTag()) {
		if tagRef, ok := img.TagName(); ok {
			keys = append(keys, tagRef)
		}
	}
	if !skipDigests {
		dgsts, err := ociClient.GetImageDigests(ctx, img)
		if err != nil {
			return 0, fmt.Errorf("could not get digests for image %s: %w", img.String(), err)
		}
		keys = append(keys, dgsts...)
	}
	err := router.Advertise(ctx, keys)
	if err != nil {
		return 0, fmt.Errorf("could not advertise image %s: %w", img.String(), err)
	}
	return len(keys), nil
}
