package pipeline

import data.lib

all_denies := lib.current_and_future_denies("pipeline")

all_warns := lib.current_and_future_warns("pipeline")

deny := lib.current_rules(all_denies)

warn := lib.future_rules(all_denies) | lib.current_rules(all_warns)
