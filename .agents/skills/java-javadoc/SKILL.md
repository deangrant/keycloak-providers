---
name: java-javadoc
description: >-
  Write and update JavaDoc for Java APIs in this repo so comments stay compatible
  with Spotless Google Java Format and Error Prone Javadoc checks. Use when adding
  or changing public/protected types or members, documenting SPI or extension
  points, improving existing JavaDoc, or when the user asks for Java documentation
  comments.
---

# JavaDoc

Write JavaDoc that is useful in source and safe for this repo’s linters: Spotless
(Google Java Format) and Error Prone (default Javadoc checks).

For concrete good/bad snippets, see [examples.md](examples.md).

## When to document

**Required** for visible API: `public` / `protected` types and members that are
not trivial overrides.

**Skip or keep minimal:**

- Trivial getters/setters when the name is the full story
- Overrides that inherit docs (`@Override` only; add JavaDoc only when behavior
  differs)
- Package-private / private members unless the contract is non-obvious

Prefer **no comment** over a comment that only restates the identifier.

## Summary fragment

Every Javadoc block on a public/protected member must start with a **summary
fragment** (Error Prone `MissingSummary`):

- Capitalized noun or verb phrase, ends with `.`
- Adds information beyond the name (side effects, nullability, auth impact,
  config keys, SPI id, and so on)
- **Not** `This method…`, `A Foo is a…`, or a block that is only `@return …`

```java
/** Returns the provider id registered with Keycloak. */
/** Creates a user when missing and {@code forceCreate} is enabled. */
```

## Formatting (Spotless / Google Java Format)

- Use `/** … */` with each continuation line starting ` *` (one space after `*`)
- One blank ` *` line between paragraphs and before the block-tag group
- Continuation paragraphs: put `<p>` **immediately before** the first word (no
  space after `<p>`; do **not** put `<p>` alone on a line)
- Do **not** put `<p>` before other block HTML (`<ul>`, `<pre>`, …)
- Single-line `/** … */` only when the whole block fits one line **and** there
  are no block tags
- Block-tag order: `@param` (declaration order) → `@return` → `@throws` →
  `@see` → `@since` → `@deprecated` (and similar); no blank lines between tags

```java
/**
 * Sends a one-time magic link to the user's email.
 *
 * <p>When {@code forceCreate} is enabled, creates the user if none exists.
 *
 * @param context authentication flow context; never {@code null}
 * @return {@code true} if the email was accepted for delivery
 */
```

## Tags and markup

- Use `{@code …}` for names and literals; `{@link Type}` / `{@link #member}` for
  types and members
- Inline tags must be well-formed: `{@code x}`, never `@{code x}`
  (`MalformedInlineTag`)
- Escape bare `<`, `>`, `&` in prose, or wrap identifiers in `{@code}`
  (`UnescapedEntity`)
- `@param` / `@return` / `@throws` / `@deprecated` must have a non-empty
  description (`EmptyBlockTag`); omit the tag if there is nothing useful to say
- `@param` names must match real parameters (`InvalidParam`)
- Prefer `@throws` over `@exception`
- Do not invent unknown block tags (`InvalidBlockTag`)
- Never put `@param`, `{@link}`, or HTML docs inside `/* … */`
  (`AlmostJavadoc` / `NotJavadoc`)

Document nullability and when exceptions occur when that is part of the
contract. Class-level docs may say how to obtain or enable the type (SPI id,
factory, browser-flow placement) when that is the valuable content.

## Error Prone checklist

Before finishing JavaDoc edits, confirm none of these apply:

- [ ] `MissingSummary` — summary fragment present
- [ ] `EmptyBlockTag` — no empty `@param` / `@return` / `@throws` / `@deprecated`
- [ ] `AlmostJavadoc` / `NotJavadoc` — docs use `/**`, not `/*`
- [ ] `MalformedInlineTag` — `{@code}` / `{@link}` spelled correctly
- [ ] `InvalidParam` / `InvalidBlockTag` / `InvalidInlineTag` — tags match reality
- [ ] `UnescapedEntity` — no bare `<` / `>` / `&` in prose

## Workflow

1. Decide whether JavaDoc is required or would be zero-value noise.
2. Write the summary fragment first.
3. Add body paragraphs and tags only for non-obvious contracts.
4. Run the checklist above.
5. After Java edits: `mvn -B spotless:apply` (then verify/test per
   `java-maven` rules when the change is meaningful).
