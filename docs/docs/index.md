---
title: Warden Supreme
hide:
  - navigation
  - toc
---

<link rel="stylesheet" href="stylesheets/landing.css">
<script>
  document.addEventListener("DOMContentLoaded", () => {
    document.body.classList.add("ws-landing-page");
    const onScroll = () => {
      if (window.scrollY > 0) {
        document.body.classList.add("ws-header-scrolled");
      } else {
        document.body.classList.remove("ws-header-scrolled");
      }
    };
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
  });
</script>

{% macro icon(name, alt='') -%}
<img class="ws-icon" src="assets/icons/material/{{ name }}.svg" alt="{{ alt }}">
{%- endmacro %}

{% macro badge(icon_name, label) -%}
<span class="ws-badge">{{ icon(icon_name, label) }}<span>{{ label }}</span></span>
{%- endmacro %}

{% macro hero_card(icon_name, label) -%}
<div class="ws-art__card">
  {{ icon(icon_name, label) }}
  <span>{{ label }}</span>
</div>
{%- endmacro %}

{% macro feature_card(icon_name, title, body) -%}
<div class="ws-card">
  <div class="ws-card__header">
    <div class="ws-card__icon">{{ icon(icon_name, title) }}</div>
    <h3>{{ title }}</h3>
  </div>
  <p>{{ body }}</p>
</div>
{%- endmacro %}

{% macro mini_card(icon_name, body) -%}
<div class="ws-cred__item">
  {{ icon(icon_name) }}
  <p>{{ body }}</p>
</div>
{%- endmacro %}

{% macro step_card(step, title, body) -%}
<div class="ws-step">
  <div class="ws-card__header">
    <div class="ws-step__num">{{ step }}</div>
    <h3>{{ title }}</h3>
  </div>
  <p>{{ body }}</p>
</div>
{%- endmacro %}

{% macro team_card(icon_name, title, body, link1, href1, link2, href2) -%}
<div class="ws-card">
  <div class="ws-card__header">
    <div class="ws-card__icon">{{ icon(icon_name, title) }}</div>
    <h3>{{ title }}</h3>
  </div>
  <p>{{ body }}</p>
  <a class="ws-link" href="{{ href1 }}">{{ link1 }}</a>
  <a class="ws-link" href="{{ href2 }}">{{ link2 }}</a>
</div>
{%- endmacro %}

{% macro doc_card(icon_name, title, body, link1, href1, link2='', href2='') -%}
<div class="ws-card">
  <div class="ws-card__header">
    <div class="ws-card__icon">{{ icon(icon_name, title) }}</div>
    <h3>{{ title }}</h3>
  </div>
  <p>{{ body }}</p>
  <a class="ws-link" href="{{ href1 }}">{{ link1 }}</a>
  {% if link2 %}<a class="ws-link" href="{{ href2 }}">{{ link2 }}</a>{% endif %}
</div>
{%- endmacro %}

<h1><img  src="assets/images/supreme-horz.png" alt="Warden Supreme"></h1>
<div class="md-grid">
      <div class="ws-hero__panel">
 <h2>End-to-End Integrated Attestation for Android and iOS – Unified, Production-Ready.</h2>
<div class="ws-badges">
              {{ badge('android', 'Android') }}
              {{ badge('apple', 'iOS') }}
              {{ badge('file-certificate', 'Policy-driven') }}
              {{ badge('shield-star', 'Battle-tested') }}
              {{ badge('code-tags', 'Open-Source') }}
            </div>

        <div class="ws-hero__grid">
          <div class="ws-hero__content">
            <p>
              Let your sevice verify app and device integrity using platform attestation.
              Warden Supreme hides all complexity behind a single, unified API across your stack.<br>
              Define a policy, plug in the verifier, certify hardware‑backed keys. </p>

            <div class="ws-cta-row">
              <a class="md-button md-button--primary ws-cta" href="integration/supreme/">Get started</a>
              <a class="md-button ws-cta" href="overview/">Read the Docs</a>
              <a class="md-button ws-cta" href="services/">Services</a>
            </div>

            <div class="ws-proof">
              {{ icon('chart-line', 'Proof') }}
              <p>Millions of devices attested in production – and counting.</p>
            </div>
          </div>

          <div class="ws-hero__art" aria-hidden="true">
            <div class="ws-art">
              <div class="ws-art__glow"></div>
               <img src="assets/images/supreme-hero.svg" alt="Warden Supreme hero"/>
            </div>
        </div>
      </div>
    </div>

  <section class="ws-section">
    <div class="md-grid">
      <h2>Why Warden Supreme?</h2>
      <div class="ws-cards ws-cards--features">
        {{ feature_card('security', 'Unified Verification', 'One verifier for Android Key Attestation and Apple App Attest.') }}
        {{ feature_card('layers', 'One Consistent API', 'Shared APIs across server, Android and iOS clients.') }}
        {{ feature_card('file-certificate', 'Policy-Driven Checks', 'Define and evolve verification policies without client rewrites.') }}
        {{ feature_card('speedometer', 'Get Going, Fast', 'Client integration in five lines of code – no cheap tricks, no sleight of hand.') }}
        {{ feature_card('check-decagram', 'Production-Proven', 'Built on the battle-tested WARDEN stack, now consolidated and refined.') }}
        {{ feature_card('shield-alert', 'Risk-Based', 'Grounded in threat modelling and platform characteristics – privacy-first.') }}
      </div>
    </div>
  </section>

  <section class="ws-section ws-steps">
    <div class="md-grid">
      <h2>How It Works</h2>
      <div class="ws-steps__grid">
        {{ step_card('1', 'Define Policy', 'Specify what "trusted" means in your environment. Your policy, your rules.') }}
        {{ step_card('2', 'Plug in Verifier', 'Add two HTTPS endpoints to your service and connect the verifier.') }}
        {{ step_card('3', 'Integrate into Apps', 'Five lines of code is all it takes.') }}
        {{ step_card('4', 'Issue Certificates', 'Create hardware‑backed keys and certify them based on your policy.') }}
      </div>
    </div>
  </section>

  <section class="ws-section" id="docs-hub">
    <div class="md-grid">
      <h2>Explore the Docs</h2>
      <div class="ws-cards ws-cards--docs">
        {{ doc_card('book-open-page-variant', 'Background', 'Attestation primer, threat models, platform specifics, and privacy.', 'Start here', 'bg/primer/') }}
        {{ doc_card('cogs', 'Technical Deep Dive', 'Android attestation, iOS App Attest, and platform quirks.', 'Android', 'technical/android/', 'iOS', 'technical/ios/') }}
        {{ doc_card('rocket-launch', 'Integration', 'End-to-end implementation guide, config, and data model.', 'Get started', 'integration/supreme/') }}
        {{ doc_card('book-alphabet', 'Glossary', 'Terminology and definitions across all things attestation.', 'Browse glossary', 'glossary/') }}
      </div>
    </div>
  </section>

  <section class="ws-section ws-funding">
    <div class="md-grid">
      <p class="ws-funding__text">
        This project has received funding from the European Union's Horizon 2020 research and innovation
        programme under grant agreement No 959072.
      </p>
      <p class="ws-funding__logo">
        <img src="assets/images/eu.svg" alt="EU flag">
      </p>
    </div>
  </section>
</div>
</div>
