#include "utils.h"

void fill_kindling_event_param(kindling_event_t_for_go* p_kindling_event, KeyValue raw_params[],
                               int raw_param_len, int& userAttNumber) {
  for (int i = 0; i < raw_param_len; i++) {
    strcpy(p_kindling_event->userAttributes[userAttNumber].key, raw_params[i].key);
    memcpy(p_kindling_event->userAttributes[userAttNumber].value, raw_params[i].value,
           raw_params[i].len);
    p_kindling_event->userAttributes[userAttNumber].valueType = raw_params[i].valueType;
    p_kindling_event->userAttributes[userAttNumber].len = raw_params[i].len;
    userAttNumber++;
  }
}