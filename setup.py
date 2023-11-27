#!/usr/bin/env python3

from setuptools import Extension, setup

setup(
    ext_modules=[
        Extension(
            name="defaultconf._bsdnetlink",  # as it would be imported
            sources=["_bsdnetlink.c"], # all sources are compiled into a single binary file
        ),
    ]
)

