# SP3CTR - Dev Diary #8
## *Or: How I Learned to Stop Worrying and Love SQL*

**Faith in Project:** Manic  
**Sleep Debt:** Collateral Damage  
**Entry by:** KnifeySpooney

---

So, we did a thing. The thing you're *never* supposed to do. We looked at a perfectly functional, if slightly janky, piece of software and said, **"Let's get this to version 1.0. In a weekend."** This is the kind of hubris that usually precedes a catastrophic `git rebase` and a long, soul-searching stare into the abyss of a compiler error log.

The goal was simple: take the existing SP3CTR, with its *charming* memory leaks and penchant for self-immolation, and forge it into something that wouldn't fall over if you looked at it funny.

---

## Act I: Slaying the Memory Dragon 🐉

The **original sin** of this codebase, the foundational flaw upon which all other problems were built, was a single, innocent-looking line:

```python
captured_packets_buffer = []
```

A Python list. So helpful. So simple. And so *utterly, catastrophically ruinous*.

It wasn't just storing packet data; it was holding the entire, multi-layered, computationally expensive **Scapy packet object** in RAM. Five minutes on a busy network and you could watch the app's memory usage climb like a homesick angel, bloating from a respectable 100MB to a gigabyte, then two, before the OS would unceremoniously execute it for being a glutton.

The solution was obvious: **stop being lazy and use a proper database.**

We performed a full architectural transplant. The in-memory list was ripped out of the core and replaced with a temporary `session.db` created for each capture. Every incoming packet is now serialized with `pickle` (Python's beautiful, horrifying duct tape for complex objects) and entombed in a BLOB field. The app's memory footprint is now *flat*. Constant. Beautifully, smugly **boring**.

But that created a new problem: **speed**. You can't query a database hundreds of times per second to update a live UI without it feeling like wading through molasses.

So, we built a **hybrid engine**. A 200-packet `collections.deque` now acts as a high-speed, fixed-size cache on both the backend and frontend. New packets push the oldest ones into the void. The UI gets its smooth, real-time feed directly from this RAM cache, while the SQLite database on disk quietly shoulders the burden of history, its performance boosted by `PRAGMA journal_mode=WAL;` to stop the reading and writing threads from getting into a fistfight over file locks.

*It's the mullet of data architecture: business in the back, party in the front.*

---

## Act II: The Exorcism Rite 🛡️

With the core architecture no longer actively trying to set the computer on fire, we could finally address the **ghosts haunting the machine**.

### Ghost #1: The Poltergeist

You'd click **Start**, then **Stop**, then **Start** again in quick succession, and the backend would scream bloody murder. The log would flash a `[WinError 32]`, a cryptic curse telling me the `session.db` file was *"being used by another process."*

Of course it was. The ghost of the last capture thread, still moaning as it slowly faded from existence, hadn't finished releasing its file handle before the new thread tried to burn the house down and rebuild on the same spot.

**The fix?** A proper ghost trap: a `threading.Lock` and a real state machine (`STARTING`, `RUNNING`, `STOPPING`). Now, the application logic is a bouncer. It checks the ID of the current state:

> *"Is the capture STOPPED? Cool, you can come in. Oh, it's STOPPING? Sorry pal, you'll have to wait till it's finished."*

No more race conditions.

### Ghost #2: The Commitment-Phobe

Yank the ethernet cable, and the whole backend would just... *vanish*. No error, no log, no "farewell, cruel world."

Deep inside Scapy, the `sniff()` function would have an existential crisis, throw a fatal, unhandled exception, and the thread would simply **cease to exist**, taking the whole server with it.

**The solution?** Give the sniffer some therapy in the form of a broad `try...except Exception as e:` block. Now, when the network abandons it, it doesn't just give up on life. It catches the exception, logs the tragic event, sends a clear *"I've been abandoned!"* error message to the UI, and shuts down gracefully.

### Ghost #3: The Liars

Malformed DNS packets would come in, whispering sweet nothings in their `ancount` header field—*"I swear, I have an answer record for you!"*—and the code, in its youthful naivety, would believe them.

It would start a `for` loop to iterate through the promised `DNSRR` layers, only for Scapy's dissection to come up empty. The code would try to access a layer that didn't exist and fall headfirst into an `IndexError` abyss.

**The fix?** We made the code **cynical**. It no longer trusts any packet. It now wraps every DNS read in its own `try...except IndexError`, and if a packet lies, it gets logged with the contempt it deserves before being discarded.

---

## Act III: A Fresh Coat of Paint on a Cleansed House 🎨

With the demons banished, I was left with a stable, reliable application that looked like it was designed in **2005**. The foundation was solid, but the house was *ugly*. There was only one thing to do: a full gut renovation.

Inspired by the clean, no-nonsense world of Swift UI *(it's a long story)*, I tore down everything:

- **The clunky, centered `<h1>` is gone**, replaced by a sleek flexbox header with the title and version on one side and live-updating stats for **Total Packets** and **Total Data** on the other.

- **The bandwidth chart was freed from its container**, its title restyled into a modern tab with a `border-b-2 border-cyan-400`. The ugly block legend was nuked and replaced with a clean, integrated list of dot-points.

- We even gave the chart a gorgeous **gradient fill** using `createLinearGradient`. It's the same data, but now it has *confidence*.

- We added a **heartbeat**—a live "Packets Per Second" counter that gives the whole dashboard a sense of pulse, of *life*.

- And for the grand finale of form over function, we built the **"cinematic" save progress bar**. It's pure, unapologetic UI vanity. On click, it starts a timer and smoothly animates to 95% width. It just sits there, looking *busy*, while the backend does the actual work in the background. When the "save complete" message finally arrives, it zips to 100%, and an SVG checkmark animates in.

**It's pointless. And I love it.**

---

## Act IV: Release Candidate 1.0 🏁

And just like that, it was **done**.

We ran the checklist, squashed the ghosts, and gave it a facelift. It's not just "functional" anymore. It's **stable**. It's **polished**. It's `v1.0.0-RC1`.

The sprint was brutal, fueled by an unhealthy amount of caffeine and a stubborn refusal to accept defeat. But we dragged this thing, kicking and screaming, across the finish line.

**It's ready.**

Now, about that PCAP viewer you may need...

---

*// KS*
