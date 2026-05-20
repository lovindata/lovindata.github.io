---
title: "Event Bus 🚌: The One Pattern Quietly Powering Revolut, Paytm, and Block"
date: 2026-05-20
categories:
  - Kafka
  - Python
  - FastAPI
  - Docker
  - Traefik
  - Backend
  - DevOps
---

When I joined the company as a mid-level engineer, our system was still relatively simple, with a handful of [microservices](https://en.wikipedia.org/wiki/Microservices) 🧩 directly calling each other. However, as the team grew and we scaled our infrastructure with [Kubernetes](https://kubernetes.io/) ☸️ and multiple replicas, this tight [coupling](<https://en.wikipedia.org/wiki/Coupling_(computer_programming)>) quickly turned into a massive bottleneck. At one point, I was responsible for a part of the service landscape, which gave me a clear view of how fragile things were getting—a reality that hit hard when we integrated a new asynchronous [payment system](https://en.wikipedia.org/wiki/E-commerce_payment_system) 💳. This system pushed critical [transaction events](https://en.wikipedia.org/wiki/Transaction_data) involving substantial sums of money, making it absolutely vital that we handled every single payload flawlessly. Ultimately, we reworked the [architecture](https://en.wikipedia.org/wiki/Software_architecture) and introduced an event bus 🚌 to process these interactions [asynchronously](https://en.wikipedia.org/wiki/Asynchronous_communication) ⚡. This shift gave us the ironclad reliability we needed to safely manage those high-value events, leaving the entire system far more stable and maintainable—just sharing a bit of what I’ve learned along the way 🚀.

<!-- more -->

![Kafka](image-1.png)

## 🚌 What is an Event Bus?

Before diving into the event bus itself, let's break down the main players involved:

- [**📤 Producer**](https://en.wikipedia.org/wiki/Publish%E2%80%93subscribe_pattern): Any service that publishes events without knowing or caring who consumes them.
- [**🚌 Event bus**](https://en.wikipedia.org/wiki/Message_bus): The backbone — a durable channel that transports events from producers to consumers.
- [**📦 Event**](<https://en.wikipedia.org/wiki/Event_(computing)>): A structured message representing something that happened (e.g., `payment.received` or `order.shipped`).
- [**📥 Consumer**](https://en.wikipedia.org/wiki/Publish%E2%80%93subscribe_pattern): A service that subscribes to specific events and reacts when they arrive.

In simple terms, the producer enqueues an event into the bus, and the consumer picks it up whenever it's ready. They never talk to each other directly — the bus mediates everything.

<figure markdown="span">
  ![Event bus pattern](image.png)
  <figcaption>Event bus pattern</figcaption>
</figure>

But why not just HTTP? I asked myself the same question — until I spent three days debugging a background job bouncing between three replicated microservices. Services calling each other, but with also three replicas of each, which instance handled what? I'd grep every replica, cross-reference timestamps, and still get a fragmented mess. There was no single place to see the full sequence 🫠. That's when it clicked: **Without a central bus, you're trading tomorrow's debugging sanity for today's simplicity.**

At my company, I mainly used the event bus to tackle two specific scenarios: decoupling services that had grown too dependent on each other, and handling asynchronous communication where reliability was non-negotiable. Event buses can do much more — think [CQRS](https://en.wikipedia.org/wiki/CQRS) for read-heavy systems — but I'll stick to what I've lived through 🚀.

### Decoupling microservices at scale

TODO HERE!

When we first started scaling our services across multiple K8s replicas ☸️, each deployment tracked a hardcoded list of URLs for every other service it needed to talk to. A new replica rolled out? Update the config. A service moved? Update the config. A single endpoint slowed down? The timeout propagated everywhere and brought unrelated features down with it.

We switched to an event bus pattern: services that previously called HTTP endpoints **started publishing events instead**. The bus buffered and routed them, and consumers picked them up when they were ready. Suddenly, scaling a service up or down had zero impact on its downstream dependencies. No more cascading failures, no more URL wrangling 🧩.

### Handling high-stakes async communication

Then came the payment system integration. This was the one that kept me up at night 😅. Every transaction event carried real money 💳, and every single one had to land — no exceptions. With direct HTTP, a network hiccup or a momentary service restart could silently drop a payment notification. The business impact was obvious.

The event bus changed everything. Events **persisted to disk**, survived service restarts, and were retried with exponential backoff until the consumer acknowledged them. The producer got a confirmation that the event was safely stored, not just sent. For the first time, I could sleep knowing that a transient failure wouldn't lose a single euro.

## All you need to know about Kafka

## Example: A Fintech Payment Flow
