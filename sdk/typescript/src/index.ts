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

export class BlindfoldBoundary {
  readonly #mappings = new Map<string, Mapping>();
  #sequence = 0;

  tokenize(value: string, kind: TokenKind): string {
    if (value.length === 0) {
      throw new Error("cannot tokenize an empty value");
    }
    const existing = this.#find(value, kind);
    if (existing !== undefined) {
      return existing;
    }
    this.#sequence += 1;
    const token = `{{BLINDFOLD:SDK:v1:${kind.toUpperCase()}:${String(this.#sequence).padStart(6, "0")}}}`;
    this.#mappings.set(token, { kind, value });
    return token;
  }

  toLLM(input: string, values: ReadonlyArray<{ value: string; kind: TokenKind }>): TokenizedText {
    let text = input;
    let replacements = 0;
    for (const item of values) {
      if (item.value.length === 0) {
        continue;
      }
      const token = this.tokenize(item.value, item.kind);
      const parts = text.split(item.value);
      replacements += parts.length - 1;
      text = parts.join(token);
    }
    return { text, replacements };
  }

  fromLLM(input: string, destination: Destination): string {
    return input.replace(
      /\{\{BLINDFOLD:SDK:v1:(SECRET|PII):[0-9]{6}\}\}/g,
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
}
