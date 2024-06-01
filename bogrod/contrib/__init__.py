from .dummy import DummyAggregator
from .elementaris import EssentxElementaris

aggregators = {
    'elementaris': EssentxElementaris,
    'dummy': DummyAggregator,
}
