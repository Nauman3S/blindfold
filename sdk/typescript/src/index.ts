import { randomBytes } from "node:crypto";

export type Destination = "llm" | "end_user" | "log" | "memory" | "tool";
export type TokenKind = "secret" | "pii";

export interface TokenizedText {
  readonly text: string;
  readonly replacements: number;
}

interface Mapping {
  readonly kind: TokenKind;
  readonly value: string;
}

const TOKEN_PATTERN = /\{\{BLINDFOLD:SDK:v1:(SECRET|PII):[0-9a-f]{32}\}\}/g;

export class BlindfoldBoundary {
  readonly #mappings = new Map<string, Mapping>();

  tokenize(value: string, kind: TokenKind): string {
    return this.#tokenize(value, kind, value);
  }

  #tokenize(value: string, kind: TokenKind, source: string): string {
    if (value.length === 0) {
      throw new Error("cannot tokenize an empty value");
    }
    const existing = this.#find(value, kind);
    if (existing !== undefined) {
      return existing;
    }
    const token = this.#createToken(kind, source);
    this.#mappings.set(token, { kind, value });
    return token;
  }

  toLLM(input: string, values: ReadonlyArray<{ value: string; kind: TokenKind }>): TokenizedText {
    const orderedValues = values
      .filter((item) => item.value.length > 0)
      .map((item, index) => ({ ...item, index }))
      .sort((left, right) => right.value.length - left.value.length || left.index - right.index);
    const chunks: string[] = [];
    let replacements = 0;
    let offset = 0;
    while (offset < input.length) {
      const item = orderedValues.find((candidate) => input.startsWith(candidate.value, offset));
      if (item === undefined) {
        chunks.push(input[offset]);
        offset += 1;
        continue;
      }
      chunks.push(this.#tokenize(item.value, item.kind, input));
      replacements += 1;
      offset += item.value.length;
    }
    return { text: chunks.join(""), replacements };
  }

  fromLLM(input: string, destination: Destination): string {
    return input.replace(
      TOKEN_PATTERN,
      (token: string): string => {
        const mapping = this.#mappings.get(token);
        if (mapping === undefined) {
          return token;
        }
        if (mapping.kind === "secret") {
          throw new Error("secret restoration is not allowed");
        }
        if (destination !== "end_user") {
          throw new Error("PII restoration requires the end_user destination");
        }
        return mapping.value;
      },
    );
  }

  clear(): void {
    this.#mappings.clear();
  }

  #find(value: string, kind: TokenKind): string | undefined {
    for (const [token, mapping] of this.#mappings) {
      if (mapping.value === value && mapping.kind === kind) {
        return token;
      }
    }
    return undefined;
  }

  #createToken(kind: TokenKind, source: string): string {
    for (;;) {
      const token = `{{BLINDFOLD:SDK:v1:${kind.toUpperCase()}:${randomBytes(16).toString("hex")}}}`;
      if (source.includes(token) || this.#mappings.has(token)) {
        continue;
      }
      let collidesWithMapping = false;
      for (const mapping of this.#mappings.values()) {
        if (mapping.value.includes(token)) {
          collidesWithMapping = true;
          break;
        }
      }
      if (!collidesWithMapping) {
        return token;
      }
    }
  }
}
