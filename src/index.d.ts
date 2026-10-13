import type { Report, PolicyOptions, Severity, RuleInfo } from './core.js';
export interface RawFinding { rule: string; file: string; line: number; location: string; message: string; severity?: Severity; evidence?: string; fix?: string; }
export * from './core.js';
export interface Instruction { instruction: string; args: string; line: number; raw: string; }
export interface LintInput { name: string; text: string; kind?: 'dockerfile' | 'compose'; dockerignore?: string | null; }
export interface LintOptions extends PolicyOptions { context?: string; }
export declare const VERSION: string;
export declare const TOOL: { name: string; version: string; rules: Record<string, RuleInfo>; title: string; emoji: string; defaultFailOn: Severity };
export declare const RULES: Record<string, RuleInfo>;
export declare const EOL: Array<Record<string, unknown>>;
export declare const SECRET_PATTERNS: Array<{ name: string; re: RegExp }>;
export declare function parseDockerfile(text: string): Instruction[];
export declare function lintDockerfile(text: string, file: string, ctx?: { dockerignore?: string | null }): RawFinding[];
export declare function lintCompose(text: string, file: string): RawFinding[];
export declare function findSecret(text: string): { name: string; value: string } | null;
export declare function parseYaml(text: string): any;
export declare function isDockerfile(name: string): boolean;
export declare function isCompose(name: string): boolean;
/** Lint paths (files or directories) or in-memory inputs. */
export declare function lint(inputs: Array<string | LintInput>, opts?: LintOptions): Report;
