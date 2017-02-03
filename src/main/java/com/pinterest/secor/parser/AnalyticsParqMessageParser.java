/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.pinterest.secor.parser;

import com.pinterest.secor.common.SecorConfig;
import com.pinterest.secor.message.Message;
import net.minidev.json.JSONObject;
import net.minidev.json.JSONValue;
import org.joda.time.LocalDateTime;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * LogstashMessageParser extracts timestamp field (specified by 'message.timestamp.name')
 * usually named @timestamp in logstash.
 * It uses the ISODateTimeFormat from joda-time library. Used by elasticsearch / logstash
 *
 * @see http://joda-time.sourceforge.net/apidocs/org/joda/time/format/ISODateTimeFormat.html
 *
 * @author Pablo Delgado (pablete@gmail.com)
 *
 */
public class LogstashMessageParser extends MessageParser {
    private static final Logger LOG = LoggerFactory.getLogger(LogstashMessageParser.class);
    protected static final String defaultType = "untyped";
    protected static final String defaultDate = "1970/01/01/00";

    public LogstashMessageParser(SecorConfig config) {
        super(config);
    }
    @Override
    public ParsedMessage parse(final Message message) throws Exception {
        jsonObject = (JSONObject) JSONValue.parse(message.getPayload());
        try {
            if (shouldIncludeinLake()) {
               return super.parse(message);
            }
            return null;
        } finally {
            jsonObject = null;
        }
    }

    @Override
    public String[] extractPartitions(Message message) {
        JSONObject jsonObject = (JSONObject) JSONValue.parse(message.getPayload());
        String result[] = {defaultType, defaultDate};

        if (jsonObject != null) {
            Object fieldType  = jsonObject.get(mConfig.getMessageTypeName());       //type
            Object fieldValue = jsonObject.get(mConfig.getMessageTimestampName());  //@timestamp
            if (fieldType != null) {
                result[0] = sanitizePath(fieldType.toString());
            }
            if (fieldValue != null) {
                try {

                    DateTimeFormatter inputFormatter = ISODateTimeFormat.dateOptionalTimeParser();
                    LocalDateTime datetime = LocalDateTime.parse(fieldValue.toString(), inputFormatter);
                    result[1] = datetime.toString(mConfig.getMessageTimestampBucketFormat());
                } catch (Exception e) {
                    LOG.warn("date = " + fieldValue.toString()
                            + " could not be parsed with ISODateTimeFormat."
                            + " Using date default=" + defaultDate);
                }
            }
        }

        return result;
    }

    private String sanitizePath(String path_type) {
      //Accept only lowercase underscores and hypens
      return path_type.replaceAll("\\.","-").replaceAll("[^a-zA-Z0-9-_]", "").replaceAll("---","-").replaceAll("--","-").replaceAll("___","_").replaceAll("__","_").toLowerCase();
    }
    private boolean shouldIncludeinLake() {
        if (jsonObject == null) {
            return false;
        }
        if (!jsonObject.containsKey("properties")) {
            return false;
        }
        if (!jsonObject.containsKey("event")) {
            return false;
        }
        final Object eventObject = jsonObject.get("event");
        final Object propertiesObject = jsonObject.get("properties");
        if (!(propertiesObject instanceof JSONObject)) {
            return false;
        }
        final JSONObject properties = (JSONObject) propertiesObject;
        if (!properties.containsKey("platform")) {
            return false;
        }
        final Object platformObject = properties.get("platform");
        if (!(platformObject instanceof String)) {
            return false;
        }
        final String platform = (String) platformObject;
        final String event_name = (String) eventObject;

        final boolean ret = "session_start".equals(event_name);
        if (ret) {
            ++IncludeCount;
            final Instant now = Instant.now();
            if (now.isAfter(lastFilterLog.plus(FILTER_LOG_THRESH))) {
                LOG.info("filtered For session_start payloads for Data LAke: {}", IncludeCount);
                lastFilterLog = now;
            }
        }
        return ret;
    }

}
