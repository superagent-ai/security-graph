package catalog

import (
	"math"
	"regexp"
	"strings"
	"unicode"
)

// Ranking changes invalidate continuation offsets, not immutable catalog IDs.
const optionsSearchVersion = "ranked-1"

var catalogIdentifier = regexp.MustCompile(`^(?:cwe[-_ ]?[0-9]+|[a-z0-9_-]+:[a-z0-9._-]+)$`)

type searchDocument struct {
	ids, names    []string
	primary, body map[string]bool
}

func searchWords(value string) []string {
	words := strings.FieldsFunc(strings.ToLower(value), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	out := []string{}
	for _, word := range words {
		switch word {
		case "a", "an", "and", "are", "as", "at", "be", "been", "by", "can", "for", "from", "in", "into", "is", "it", "of", "on", "or", "that", "the", "their", "this", "to", "using", "via", "when", "where", "which", "with":
			continue
		}
		if len(word) > 4 && strings.HasSuffix(word, "s") && !strings.HasSuffix(word, "ss") {
			word = strings.TrimSuffix(word, "s")
		}
		out = append(out, word)
	}
	return out
}

func wordSet(values ...string) map[string]bool {
	out := map[string]bool{}
	for _, value := range values {
		for _, word := range searchWords(value) {
			out[word] = true
		}
	}
	return out
}

func document(ids []string, names []string, description string) searchDocument {
	return searchDocument{ids: ids, names: names, primary: wordSet(append(ids, names...)...), body: wordSet(description)}
}

type catalogSearch struct {
	query, phrase  string
	identifier     bool
	words          []string
	weights        map[string]float64
	types, entries map[string]searchDocument
}

func newCatalogSearch(c Catalog, query string) catalogSearch {
	s := catalogSearch{query: query, phrase: strings.Join(searchWords(query), " "), identifier: catalogIdentifier.MatchString(query), weights: map[string]float64{}, types: map[string]searchDocument{}, entries: map[string]searchDocument{}}
	frequency := map[string]int{}
	count := 0
	add := func(d searchDocument) {
		count++
		for word := range d.primary {
			frequency[word]++
		}
		for word := range d.body {
			if !d.primary[word] {
				frequency[word]++
			}
		}
	}
	for _, t := range c.Types {
		if !t.Classifiable || t.Deprecated {
			continue
		}
		d := document([]string{t.ID, t.CWEID}, append([]string{t.Name}, t.Aliases...), t.Description)
		s.types[t.ID] = d
		add(d)
	}
	for _, e := range c.Entries {
		if e.Deprecated {
			continue
		}
		d := document([]string{e.ID, e.ExternalID}, []string{e.Name}, e.Description)
		s.entries[e.ID] = d
		add(d)
	}
	for _, word := range searchWords(query) {
		if frequency[word] > 0 && s.weights[word] == 0 {
			// Accumulate in query order: map iteration would make floating-point
			// ties unstable between continuation requests.
			s.words = append(s.words, word)
			s.weights[word] = math.Log(1 + float64(count)/float64(frequency[word]))
		}
	}
	return s
}

func (s catalogSearch) score(d searchDocument) float64 {
	if s.query == "" {
		return 1
	}
	for _, id := range d.ids {
		if strings.EqualFold(id, s.query) || (s.identifier && strings.Join(searchWords(id), " ") == s.phrase) {
			return 1_000_000
		}
	}
	for _, name := range d.names {
		if strings.EqualFold(name, s.query) {
			return 1_000_000
		}
	}
	// A precise identifier never becomes a fuzzy numeric search. Unknown IDs
	// return no choices, rather than unrelated controls with the same number.
	if s.identifier {
		return 0
	}
	score := 0.0
	for _, word := range s.words {
		if d.primary[word] {
			score += 12 * s.weights[word]
		} else if d.body[word] {
			score += s.weights[word]
		}
	}
	for _, value := range append(append([]string{}, d.ids...), d.names...) {
		words := searchWords(value)
		phrase := strings.Join(words, " ")
		if phrase != "" && s.phrase == phrase {
			return 1_000_000
		}
		if len(words) >= 2 && strings.Contains(" "+s.phrase+" ", " "+phrase+" ") {
			score += 100 * float64(len(words))
		}
	}
	return score
}
