from .aggregator import DummyAggregator
from .elementaris import EssentxElementaris

aggregators = {
    'elementaris': EssentxElementaris,
    'dummy': DummyAggregator,
}
