# wlx - Wayland Compositor Library

> The "x" makes it sound cool

wlx is a work-in-progress and experimental Wayland compositor library, with a
focus on advanced features currently not available in other similar projects.
This is still at the proof of concept stage; you probably shouldn't take it too
"seriously" yet.

## Major Target Features

- Restart-in-place, without losing client state
- Full multi-GPU support, with hotplug
- Ability to recover from GPU resets
- "Good" explicit synchronization (with queues)
- Multi-thread capable? (Still haven't decided if this is a good idea or not)

## Why not wlroots/libweston?

In order to implement restart-in-place, I need control of **all** Wayland
protocol state (down to the protocol buffers), which means we cannot use
libwayland-server and are forced to reimplement it ourselves. libweston and
wlroots are **very** tightly coupled to libwayland-server, so it would be far
more work to try remove that compared to rewriting the whole thing.

Explicit synchronization is also a pretty extreme change to commit state
handling, which arguably makes a rewrite easier too.

## Other goals

wlx is going to be very heavily inspired by the design of wlroots, but there
are several parts of it I want to improve.

- No rendering API; provide a scene graph instead. I've gone on about this
  enough in wlroots.
- Make it **much** easier to bind to from other languages
  * No `container_of` types in the API (think `wl_list` and `wl_signal`)
  * Maybe at least 1 "official" binding to another language, to make sure we
    don't fuck it up too much.
- More focus on ABI stability
  * More opaque structs
- Avoid making the mistake that was how `wlr_output` works.
  * More thought about the lifetime of things that cross the API.
- (Optional) Dynamically loadable modules. Basically just to get optional
  dependencies, so people don't have to pull in a bunch of X11 shit to use a
  distro version of this, unless they really want to. Mainly just concerns the
  backends and Xwayland.
- Be more careful of the symbols we use, in case we're being linked statically.
- Allow "unity builds" to work. Honestly unity builds are a pretty stupid idea
  and are just a workaround to C++'s god-awful compile times (thanks to
  templates), but being able to cleanly build this way helps with the above
  point.

## Nvidia?

Hahahaha

no

## License

GPL-2.0-only.

## Targets

### Operating System
- Linux (glibc or musl)
- FreeBSD

The code is written to be as conformant to C17 and POSIX.1-2008 as possible,
but there will be some minor exceptions, either from necessity or if the value
gained from something non-portable is very high. I'll try to provide reasonable
fallbacks.

Patches for other BSDs or libcs are welcome, but its just that I probably won't
put a lot of effort into maintaining support for them, especially if the
DRM/evdev support isn't there.

### Session Managers

One of logind, elogind, or Consolekit2 is **required** for the tty session. I
will not be accepting anything that will require us to have elevated
priviledges via `setuid` or requires messing around with the tty ourselves.
