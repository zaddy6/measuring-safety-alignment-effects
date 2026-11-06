#!/usr/bin/env Rscript

# Optional final-paper model. Run after the primary 31B traces are complete and
# exported to a flat CSV with columns: success, condition, task_class, task_id,
# seed.

suppressPackageStartupMessages({
  library(lme4)
})

args <- commandArgs(trailingOnly = TRUE)
if (length(args) != 1) {
  stop("usage: mixed_effects_template.R analysis/primary_31b_repair/run_level.csv")
}

df <- read.csv(args[[1]])
df$success <- as.integer(df$success)
df$condition <- factor(df$condition)
df$task_class <- factor(df$task_class)
df$task_id <- factor(df$task_id)
df$seed <- factor(df$seed)

fit <- glmer(
  success ~ condition + task_class + (1 | task_id) + (1 | seed),
  data = df,
  family = binomial()
)

print(summary(fit))
