# Bitbox Micro Firmware: The Character Chain

Four effect slots in a row across the whole mix: Destruction, Overdrive, Colour
and Saturation. Each slot holds one of four effects, sixteen in all. Every one
is a port of a plugin by Chris Johnson of Airwindows, used under its MIT
licence.

Turn a slot's Amount up and that effect joins the mix. At zero it is gone.

## The Four Banks

Each bank is a family of four. Every effect keeps its Airwindows name, so
[the Airwindows site](https://www.airwindows.com/) has far more on each one.

### Destruction

Destruction is lo-fi and breakage, for when the mix should sound broken on
purpose: old samplers, aliasing, clang and buzz.

| # | Effect | Sound | Tone |
| :--: | ------ | ----- | ---- |
| 1 | **Pockey2** | old-sampler crunch and grit | how far the sample rate drops |
| 2 | **DeRez3** | smeared, aliased lo-fi | how few bits: harsher as you turn it up |
| 3 | **Ring Mod** | metallic, bell-like clang | the ring's pitch; fully down silences it |
| 4 | **Fracture2** | folds the wave into buzzy harmonics | where the folding starts |

### Overdrive

Drive the whole mix, from a warm valve glow to big, dirty harmonics.

| # | Effect | Sound | Tone |
| :--: | ------ | ----- | ---- |
| 1 | **Tube2** | warm valve push | how hard it is driven |
| 2 | **Drive** | straight overdrive | cuts the lows before the drive; near the top it thins and quietens |
| 3 | **Mackity** | a small desk's input overloaded | how much of the extra level is taken back |
| 4 | **Huge** | big, loud, dirty harmonics | Nasty: how harsh it gets |

### Colour

Colour is the sound of the gear rather than an effect: consoles, tape and a
transformer. It is subtle at low Amounts, and a good first stop.

| # | Effect | Sound | Tone |
| :--: | ------ | ----- | ---- |
| 1 | **Channel9** | console warmth and edge | which console: Neve, API, SSL, Teac or Mackie |
| 2 | **IronOxide5** | tape, with flutter and hiss | tape speed: slower is darker |
| 3 | **ToTape8** | a fuller tape machine, with bump and flutter | darker or brighter |
| 4 | **Coils2** | a transformer pushed hard; eases off at the very top | from a good transformer to a cheap one |

### Saturation

Saturation adds weight and density, smoothly. It is the gentlest bank and comes
last, so it rounds off everything before it.

| # | Effect | Sound | Tone |
| :--: | ------ | ----- | ---- |
| 1 | **PurestDrive** | the cleanest, most transparent saturation | how hard it drives, with the level held steady |
| 2 | **Spiral2** | smooth, rounded warmth | presence |
| 3 | **Density3** | thick, dense saturation | a low cut; its centre already thins the bass, so turn it down for full lows |
| 4 | **Mojo** | fat saturation that lifts the level | how much of the lift is taken back |

## Where It Sits

The chain comes first on the master bus, before the EQ and the compressor, so
they hear what it made. It hears every pad on Out 1 and 2, tails included. Pads
on Out 3–6 skip it. See [devices](DEVICES.md#where-they-sit).

The slot order is fixed. Destruction comes first, then Overdrive, Colour and
Saturation. You break things before you polish them.

## The Controls

Each slot has an Amount, a Tone and a way to pick its effect. They are all MIDI
CCs on **channel 1**, like the EQ and the compressor.

| Slot | Amount | Tone | Next effect | Pick effect |
| ---- | :----: | :--: | :---------: | :---------: |
| **Destruction** | CC 14 | CC 18 | CC 26 | CC 22 |
| **Overdrive** | CC 15 | CC 19 | CC 27 | CC 23 |
| **Colour** | CC 16 | CC 20 | CC 28 | CC 24 |
| **Saturation** | CC 17 | CC 21 | CC 29 | CC 25 |

Amount is how much of the effect you hear. Zero is off. An off slot costs
nothing.

Tone is each effect's most useful second control. The bank tables above say
what it does. It starts at its centre.

To choose the effect, map one of the last two columns. You only need one.

- Next effect is for a button. Each press steps to the slot's next effect and
  wraps back round after the fourth.
- Pick effect is for jumping straight to one. Its range splits into four:
  `0`–`31` is the first effect, `32`–`63` the second, `64`–`95` the third and
  `96`–`127` the fourth. Use it from a sequencer, a DAW or a controller
  snapshot, when a song should always recall the same effect.

A change of effect fades out and back in. It never clicks.

Every move shows in the pop-up, such as `OVERDRIVE  Huge` over `Amount  76%`.

![The pop-up: a dark box reading OVERDRIVE Huge on the top line and
Amount 76% beneath it.](osd-popup.png)

## Things to Know

Three things are worth knowing before you stack slots.

### CPU

One or two slots are light. All four at full, with the heaviest effect in each
bank, take about a fifth of the processor. The two tape effects in Colour are
the heaviest. To watch the load, turn on the [CPU bar](SETTINGS.md#the-cpu-bar).

![The CPU bar at three loads, stacked: green only at a light load, green into
amber at about 78%, and on into red at about 95%. A white tick marks the
recent peak.](cpu-bar.png)

### Quiet Tails Come Up

Saturation lifts quiet sound more than loud. Stack two or three slots and a
reverb tail that used to fade away hangs on, with noise you never heard before.
High makeup on the compressor lifts it again, and so does auto makeup at
extreme settings. If tails turn long and grainy, back a slot off first.

Some effects change the level as well as the sound. Match the levels first.
Then judge.

### Kept Through Power-Off

The chain survives a preset change and power-off. Each slot comes back with
the Amount, Tone and effect you left it on. See
[what they have in common](DEVICES.md#what-they-have-in-common).

The Airwindows licence travels with the patch, in [LICENSE](LICENSE).
