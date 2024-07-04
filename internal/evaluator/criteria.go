// Copyright The Enterprise Contract Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"fmt"
	"time"

	ecc "github.com/enterprise-contract/enterprise-contract-controller/api/v1alpha1"
	log "github.com/sirupsen/logrus"
)

// contains include/exclude items
// digestItems stores include/exclude items that are specific with an imageRef
// - the imageRef is the key, value is the policy to include/exclude.
// defaultItems are include/exclude items without an imageRef
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

func (c *Criteria) addItem(key, value string) {
	if key == "" {
		c.defaultItems = append(c.defaultItems, value)
	} else {
		if c.digestItems == nil {
			c.digestItems = make(map[string][]string)
		}
		c.digestItems[key] = append(c.digestItems[key], value)
	}
}

func (c *Criteria) addArray(key string, values []string) {
	if key == "" {
		c.defaultItems = append(c.defaultItems, values...)
	} else {
		if c.digestItems == nil {
			c.digestItems = make(map[string][]string)
		}
		c.digestItems[key] = append(c.digestItems[key], values...)
	}
}

func (c *Criteria) get(key string) []string {
	if items, ok := c.digestItems[key]; ok {
		items = append(items, c.defaultItems...)
		return items
	}
	return c.defaultItems
}

func computeIncludeExclude(src ecc.Source, p ConfigProvider) (*Criteria, *Criteria) {
	include := &Criteria{}
	exclude := &Criteria{}

	sc := src.Config

	// The lines below take care to make a copy of the includes/excludes slices in order
	// to ensure mutations are not unexpectedly propagated.
	if sc != nil && (len(sc.Include) != 0 || len(sc.Exclude) != 0) {
		include.addArray("", sc.Include)
		exclude.addArray("", sc.Exclude)
	}

	vc := src.VolatileConfig
	if vc != nil {
		at := p.EffectiveTime()
		filter := func(items *Criteria, volatileCriteria []ecc.VolatileCriteria) *Criteria {
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
					items.addItem(c.ImageRef, c.Value)
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
			include.addItem("", fmt.Sprintf("@%s", collection))
		}
	}

	if include.len() == 0 {
		include.addItem("", "*")
	}

	return include, exclude
}
