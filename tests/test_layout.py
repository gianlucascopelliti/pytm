#!/usr/bin/env python3

import os
import pytm
from pytm import (
    TM,
    Actor,
    Boundary,
    Dataflow,
    Datastore,
    ExternalEntity,
    Process,
    Server,
    Lambda,
    SetOfProcesses,
    Data,
    Classification,
    Rankdir,
    Rank,
    LayoutGroup
)

tm = TM("Testing layout tweaks")

tm.description="This is only for testing the DFD layout"
tm.mergeResponses = True

tm.threatsFile = os.path.abspath(os.path.join(os.path.dirname(__file__), "..")) + "/pytm/threatlib/threats.json"
    

# set ranking direction
tm.rankdir = Rankdir.LR
# tm.rankdir = Rankdir.RL
# tm.rankdir = Rankdir.TB
# tm.rankdir = Rankdir.BT

# define layoutgroups
lg0 = LayoutGroup("level0", Rank.min)
lg1 = LayoutGroup("level1", Rank.same)
lg2 = LayoutGroup("level2", Rank.same)
lg3 = LayoutGroup("level3", Rank.sink)

bnd = Boundary('Test Boundary')

actor = Actor("Actor")
actor.inLayoutGroup = lg0
actor.inBoundary = bnd

proc = Process("Process")
proc.inLayoutGroup = lg0
proc.inBoundary = bnd

procs = Process("Processes")
procs.inLayoutGroup = lg0

ds = Datastore("Datastore")
ds.inLayoutGroup = lg2

server = Server("Server")
server.inLayoutGroup = lg1

lmbda = Lambda("Lambda")
lmbda.inLayoutGroup = lg1

ext = ExternalEntity("External Entity")
ext.inLayoutGroup = lg3

atop = Dataflow(actor, proc, "A to P")

atos = Dataflow(actor, server, "A to S")

ptoa = Dataflow(proc, actor, "P to A")
ptoa.responseTo = atop

ptops = Dataflow(proc, procs, "P to Ps")

pstod = Dataflow(procs, ds, "Ps to D")
pstoe = Dataflow(procs, ext, "Ps to E")

dtos = Dataflow(ds, server, "D to S")
dtop = Dataflow(ds, proc, "D to P")
dtop.constraint = False 

stol = Dataflow(server, lmbda, "S to L")
stops = Dataflow(server, procs, "S to Ps")

stop = Dataflow(server, proc, "S to P")

ltoe = Dataflow(lmbda, ext, "L to E")
ltod = Dataflow(lmbda, ds, "L to D")

etoa = Dataflow(ext, actor, "E to A")
etol = Dataflow(ext, lmbda, "E to L")
etol.responseTo = ltoe


if __name__ == "__main__":
    tm.process()



