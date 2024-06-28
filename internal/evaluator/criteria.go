package evaluator

import (
	"fmt"
	"time"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	log "github.com/sirupsen/logrus"
)

type Criteria struct {
	digestItems  map[string][]string
	defaultItems []string
}

func (c *Criteria) len() int {
	totalLength := len(c.defaultItems)
	for _, items := range c.digestItems {
		totalLength += len(items)
	}
	return totalLength
}

func (c *Criteria) add(key, value string) {
	if key == "" {
		c.defaultItems = append(c.defaultItems, value)
	} else {
		c.digestItems[key] = append(c.digestItems[key], value)
	}
}

func (c *Criteria) addArray(key string, values []string) {
	if key == "" {
		c.defaultItems = append(c.defaultItems, values...)
	} else {
		c.digestItems[key] = append(c.digestItems[key], values...)
	}
}

func (c *Criteria) get(key string) []string {
	if items, ok := c.digestItems[key]; ok {
		return items
	}
	return c.defaultItems
}

func computeIncludeExclude(src ecc.Source, p ConfigProvider) (Criteria, Criteria) {
	include := Criteria{
		digestItems: make(map[string][]string),
	}
	exclude := Criteria{
		digestItems: make(map[string][]string),
	}

	sc := src.Config

	// The lines below take care to make a copy of the includes/excludes slices in order
	// to ensure mutations are not unexpectedly propagated.
	if sc != nil && (len(sc.Include) != 0 || len(sc.Exclude) != 0) {
		include.defaultItems = append(include.defaultItems, sc.Include...)
		exclude.defaultItems = append(exclude.defaultItems, sc.Exclude...)
	}

	vc := src.VolatileConfig
	if vc != nil {
		at := p.EffectiveTime()
		filter := func(items Criteria, volatileCriteria []ecc.VolatileCriteria) Criteria {
			for _, c := range volatileCriteria {
				from, err := time.Parse(time.RFC3339, c.EffectiveOn)
				if err != nil {
					if c.EffectiveOn != "" {
						log.Warnf("unable to parse time for criteria %q, was given %q: %v", c.Value, c.EffectiveOn, err)
					}
					from = at
				}
				until, err := time.Parse(time.RFC3339, c.EffectiveUntil)
				if err != nil {
					if c.EffectiveUntil != "" {
						log.Warnf("unable to parse time for criteria %q, was given %q: %v", c.Value, c.EffectiveUntil, err)
					}
					until = at
				}
				if until.Compare(at) >= 0 && from.Compare(at) <= 0 {
					items.add(c.ImageRef, c.Value)
				}
			}

			return items
		}

		include = filter(include, vc.Include)
		exclude = filter(exclude, vc.Exclude)
	}

	if policyConfig := p.Spec().Configuration; include.len() == 0 && exclude.len() == 0 && policyConfig != nil {
		include.addArray("", policyConfig.Include)
		exclude.addArray("", policyConfig.Exclude)
		// If the old way of specifying collections are used, convert them.
		for _, collection := range policyConfig.Collections {
			include.defaultItems = append(include.defaultItems, fmt.Sprintf("@%s", collection))
		}
	}

	if include.len() == 0 {
		include.add("", "*")
	}

	return include, exclude
}
