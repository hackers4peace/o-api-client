# o-api-client

## features

* [ ] fetch instances of ldp:Resource and ldp:Container (also DirectContainer) support for JSON-LD & Turtle
 * support paging
* [ ] reconstruct graph for uniform internal access to data
 * remove ldp:Container indirection
 * keep mapping from data to instances ldp:Container ( for HTTP POST / HTTP LINK | UNLINK )

## dependencies

### common

* node-fetch
* jsonld
* jsonld-signatures [rdf-ext issue](https://github.com/rdf-ext/discussions/issues/20)
* rdf-ext
 * rdf-parser-jsonld
 * rdf-parser-n3

## notes

### Linked Data Platform
* https://www.w3.org/TR/ldp/

#### Indirect Container
* https://www.w3.org/TR/ldp/#ldpic

### Linked Data Fragments
* http://linkeddatafragments.org/

#### Triple Fragment Pattern
* http://www.hydra-cg.com/spec/latest/triple-pattern-fragments/
