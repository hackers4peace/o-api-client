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

function base (uri) {
  return uri.replace(/#.*/, '')
}

class Client {

  /**
   * @param store
   * @param key { privPem: '', uri: '' }
   * @param deps { fetch: function(), forge: {}, jsonld: {}, jsigs: {} }
   */
  constructor (store, key, deps) {
    if (deps.jsonld && deps.forge && deps.jsigs) {
      deps.jsigs.use('jsonld', deps.jsonld)
      this.jsonld = deps.jsonld.promises
      this.jsig = deps.jsigs.promises
    }
    this.fetch = deps.fetch
    this.store = store
    this.privateKeyPem = key.privPem
    this.publicKeyUri = key.uri
  }

  /**
   * currently assumes JSON-LD responses
   * @param resourceUrl
   * @returns {Graph}
   * TODO:
   * * content negotiation application/ld+json & text/turtle
   */
  get (resourceUrl) {
    let responseUrl
    let error
    let graph
    return this.fetch(base(resourceUrl))
      .then((response) => {
        responseUrl = response.url
        if (response.status === 200) {
          return response.json()
        } else {
          error = response.status
          return
        }
      }, (err) => {
        error = err
        return Promise.resolve()
      }).then((json) => {
        if (json) {
          return parsers.jsonld.parse(json)
        } else {
          return
        }
      }).then((gr) => {
        graph = gr
        if (gr && this.store) {
          return this.store.add(responseUrl, gr)
        } else { return Promise.resolve() }
      }).then(() => {
        return { url: responseUrl, graph: graph, error: error }
      })
  }

  /**
   * @param resourceUrl
   * @param triplePattern - to use with graph.match
   * @returns {Array} - list of responses with parsed graphs
   */

  getRelated (resourceUrl, triplePattern) {
    let variable = 'subject'
    if (triplePattern.object == null) variable = 'object'
    return this.get(resourceUrl)
      .then(({ url, graph }) => {
        return Promise.all(graph.match(triplePattern.subject, triplePattern.predicate, triplePattern.object)
          .map(triple => triple[variable].nominalValue)
          .map(this.get.bind(this)))
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
      object: expand('ldp:DirectContainer') // TODO: change to IndirectContainer
    }
    return this.getRelated(resourceUrl, triplePattern)
  }

  /**
   * @param containerUrl
   * @returns {Array} - list of responses with parsed graphs
   * TODO: handle paging
   */
  getAllContained (containerUrl) {
    let triplePattern = {
      subject: containerUrl,
      predicate: expand('ldp:contains'),
      object: null
    }
    return this.getRelated(containerUrl, triplePattern)
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
