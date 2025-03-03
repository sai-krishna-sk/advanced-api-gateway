from jaeger_client import Config

def init_tracing(app):
    config = Config(
        config={
            'sampler': {'type': 'const', 'param': 1},
            'logging': True,
        },
        service_name='advanced-api-gateway',
    )
    tracer = config.initialize_tracer()
    app.config['TRACER'] = tracer
    print("Jaeger distributed tracing initialized")

