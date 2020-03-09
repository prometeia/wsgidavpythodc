# -*- coding: utf-8 -*-
from promebuilder import gen_metadata, setup

METADATA = gen_metadata(
    name="wsgidavpythodc",
    description="Custom domain controller for integrating PYTHO auth with wsgidav service",
    email="pytho_support@prometeia.it",
    keywords="pytho wsgidav",
    url="https://github.com/prometeia/wsgidavpythodc"
)

if __name__ == '__main__':
    setup(METADATA)
