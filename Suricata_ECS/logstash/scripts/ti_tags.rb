require 'json'
require 'elasticsearch'

def register(params)
    @urls = params["urls"]
    @index = params["index"]
    @ca = params["ca"]

    @client = Elasticsearch::Client.new urls: @urls, transport_options: { ssl: { ca_file: @ca } }
    # @client = Elasticsearch::Client.new urls: @urls, transport_options: { ssl: { ca_file: @ca } }, log: true
    # @client.transport.logger.formatter = proc { |s, d, p, m| "#{s}: #{m}\n" }
    # @client.transport.logger.level = Logger::INFO
end

def filter(event)
    ioc = event.get('[source][ip]')
    query = {
        "_source": {
            "includes": [
                "threat.tags",
                "threat.provider"
            ]
        },
        "query": {
            "bool": {
                "must": [
                    {
                        "terms": {
                            "threat.type": [
                                "ipv4",
                                "ip"
                            ]
                        }
                    },
                    {
                        "term": {
                            "threat.ioc": ioc
                        }
                    }
                ],
                "filter": [
                    {
                        "range": {
                            "threat.creation_time": {
                                "gte": "now-7d"
                            }
                        }
                    }
                ]
            }
        },
        "size": 10
    }
    response = @client.search index: @index, body: query.to_json

    tags = []
    providers = []
    if not response['hits']['hits'].empty? then
        response['hits']['hits'].each do |result|
            if not providers.include?(result["_source"]["threat"]["provider"])
                providers.push(result["_source"]["threat"]["provider"])
            end
            tags = tags - result["_source"]["threat"]["tags"]
            tags = tags + result["_source"]["threat"]["tags"]
        end
    end

    event.set('[threat][intelligence][tags]', tags)
    event.set('[threat][intelligence][providers]', providers)
    return [event]
end