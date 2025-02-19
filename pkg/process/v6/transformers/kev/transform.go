package kev

import (
	"regexp"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype-db/pkg/data"
	"github.com/anchore/grype-db/pkg/process/v6/transformers"
	"github.com/anchore/grype-db/pkg/process/v6/transformers/internal"
	"github.com/anchore/grype-db/pkg/provider"
	"github.com/anchore/grype-db/pkg/provider/unmarshal"
	grypeDB "github.com/anchore/grype/grype/db/v6"
)

func Transform(kev unmarshal.KnownExploitedVulnerability, state provider.State) ([]data.Entry, error) {
	return transformers.NewEntries(*internal.ProviderModel(state), getKev(kev)), nil
}

func getKev(kev unmarshal.KnownExploitedVulnerability) grypeDB.KnownExploitedVulnerabilityHandle {
	urls, notes := getURLs([]string{kev.ShortDescription, kev.RequiredAction}, kev.Notes)
	return grypeDB.KnownExploitedVulnerabilityHandle{
		Cve: kev.CveID,
		BlobValue: &grypeDB.KnownExploitedVulnerabilityBlob{
			Cve:                        kev.CveID,
			VendorProject:              kev.VendorProject,
			Product:                    kev.Product,
			VulnerabilityName:          kev.VulnerabilityName,
			DateAdded:                  internal.ParseTime(kev.DateAdded),
			ShortDescription:           kev.ShortDescription,
			RequiredAction:             kev.RequiredAction,
			DueDate:                    internal.ParseTime(kev.DueDate),
			KnownRansomwareCampaignUse: strings.ToLower(kev.KnownRansomwareCampaignUse),
			Notes:                      notes,
			CWEs:                       kev.CWEs,
			URLs:                       urls,
		},
	}
}

func getURLs(aux []string, notes string) ([]string, string) {
	bracketPattern := regexp.MustCompile(`\[(https?:\/\/[^\]]+)\]`)

	// let's keep the URLs we find in order but also deduplicate them since we're combining URLs from multiple sources
	urlSet := strset.New()
	var urls []string

	// add URLs from notes first...
	if notes != "" {
		parts := strings.Split(notes, ";")
		cleanedParts := make([]string, 0, len(parts))

		for _, part := range parts {
			part = strings.TrimSpace(part)

			if strings.HasPrefix(strings.ToLower(part), "http") {
				url := strings.ReplaceAll(part, "\\/", "/")
				if !urlSet.Has(url) {
					urlSet.Add(url)
					urls = append(urls, url)
				}
			} else if part != "" {
				cleanedParts = append(cleanedParts, part)
			}
		}

		notes = strings.Join(cleanedParts, "; ")
	}

	// ...then add URLs from the other fields
	for _, text := range aux {
		matches := bracketPattern.FindAllStringSubmatch(text, -1)
		for _, match := range matches {
			if len(match) > 1 {
				url := strings.ReplaceAll(match[1], "\\/", "/")
				if !urlSet.Has(url) {
					urlSet.Add(url)
					urls = append(urls, url)
				}
			}
		}
	}

	return urls, notes
}
