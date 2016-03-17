import rdf from 'rdf-ext'
import JsonldSerializer from 'rdf-serializer-jsonld'
import JsonldParser from 'rdf-parser-jsonld'
// import clownface from 'clownface'

/**
 * TODO
 * use new rdf.Parsers
 */
const parsers = {
  jsonld: new JsonldParser()
}

const serializers = {
  jsonld: new JsonldSerializer()
}

const profile = new rdf.Profile()
profile.setPrefix('ldp', 'http://www.w3.org/ns/ldp#')
profile.setPrefix('rdf', 'http://www.w3.org/1999/02/22-rdf-syntax-ns#')

function expand (termOrCurie) {
  return profile.resolve(termOrCurie)
}

class Client {

  /**
   * @param key { privPem: '', uri: '' }
   * @param deps { forge: {}, jsonld: {}, jsigs: {} }
   */
  constructor (key, deps) {
    deps.jsigs.use('jsonld', deps.jsonld)
    this.jsonld = deps.jsonld.promises
    this.jsig = deps.jsigs.promises
    this.fetch = deps.fetch
    this.privateKeyPem = key.privPem
    this.publicKeyUri = key.uri
  }

  /**
   * currently assumes JSON-LD responses
   * TODO: content negotiation application/ld+json & text/turtle
   * @param resourceUrl
   * @returns {Graph}
   */
  get (resourceUrl) {
    return this.fetch(resourceUrl)
      .then((response) => {
        return { url: response.url, json: response.json() }
      }).then(({ url, json }) => {
        return { url: url, graph: parsers.jsonld.parse(json) }
      })
  }

  /**
   * @param resourceUrl
   * @param triplePattern - to use with graph.match
   * @returns {Array} - list of responses with parsed graphs
   */

  getRelated (resourceUrl, triplePattern) {
    return this.fetchResource(resourceUrl)
      .then(({ url, graph }) => {
        return graph.match(triplePattern.subject, triplePattern.predicate, triplePattern.object)
          .map(triple => triple.subject.nominalValue)
          .map(this.fetchResource)
      })
  }

  /**
   * @param resourceUrl
   * TODO: @param links - optional
   * @returns {Array} - list of responses with parsed graphs
   */
  getReferencedContainers (resourceUrl) {
    let triplePattern = {
      subject: null,
      predicate: expand('rdf:type'),
      object: expand('ldp:IndirectContainer')
    }
    return this.fetchRelatedResources(resourceUrl, triplePattern)
  }

  /**
   * @param containerUrl
   * @returns {Array} - list of responses with parsed graphs
   * TODO: handle paging
   */
  getContained (containerUrl) {
    let triplePattern = {
      subject: containerUrl,
      predicate: expand('ldp:contains'),
      object: null
    }
    return this.fetchRelatedResources(containerUrl, triplePattern)
  }

  /**
   * @param doc
   * @returns {Object}
   */
  sign (graph) {
    return serializers.jsonld.serialize(graph)
      .then((json) => {
        return this.jsig.sign(json[0], {
          privateKeyPem: this.privateKeyPem,
          creator: this.publicKeyUri,
          algorithm: 'LinkedDataSignature2015'
        })
      }).then((signedJson) => {
        return parsers.jsonld.parse(signedJson)
      })
  }

  /**
   * @param doc
   * @returns {Object}
   */
  verify (graph) {
    let doc, publicKey, publicKeyOwner
    return serializers.jsonld.serialize(graph)
      .then((json) => {
        return this.jsonld.expand(json)
      }).then((expanded) => {
        let signature = expanded.find((entity) => { return entity['https://w3id.org/security#signatureValue'] })
        doc = expanded.find((entity) => { return !entity['https://w3id.org/security#signatureValue'] })
        delete signature['@id']
        doc['https://w3id.org/security#signature'] = [ signature ]
        let keyUri = signature['http://purl.org/dc/terms/creator'][0]['@id']
        return this.fetch(keyUri)
      }).then((res) => {
        return res.json()
      }).then((key) => {
        return this.jsonld.compact(key, 'https://w3id.org/security/v1')
      }).then((compacted) => {
        publicKey = compacted
        return this.fetch(publicKey.owner)
      }).then((res) => {
        return res.json()
      }).then((identity) => {
        return this.jsonld.compact(identity[0], 'https://w3id.org/security/v1')
      }).then((compacted) => {
        publicKeyOwner = compacted
        publicKeyOwner.publicKey = publicKey
        return this.jsig.verify(doc, {
          publicKey: publicKey,
          publicKeyOwner: publicKeyOwner
        })
      })
  }
}

export { Client as default }
