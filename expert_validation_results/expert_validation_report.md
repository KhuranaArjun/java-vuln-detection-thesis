# Expert Validation Report

**Generated**: 2025-09-26 02:34:03

## Dataset Overview

- **Total Samples**: 10,530
- **Vulnerability Types**: 17
- **Unique Repositories**: 1,821

### Vulnerability Type Distribution

- **Input Validation**: 2,135 samples (20.3%)
- **Unknown Security Issue**: 2,068 samples (19.6%)
- **Other Security Issue**: 1,153 samples (10.9%)
- **Configuration Error**: 1,003 samples (9.5%)
- **Path Traversal**: 961 samples (9.1%)
- **Access Control**: 738 samples (7.0%)
- **SQL Injection**: 558 samples (5.3%)
- **Command Injection**: 499 samples (4.7%)
- **Denial of Service**: 351 samples (3.3%)
- **Race Condition**: 318 samples (3.0%)
- **XSS**: 232 samples (2.2%)
- **CSRF**: 211 samples (2.0%)
- **XXE**: 129 samples (1.2%)
- **Deserialization**: 110 samples (1.0%)
- **Information Disclosure**: 44 samples (0.4%)
- **Cross-Site Scripting (XSS)**: 16 samples (0.2%)
- **Buffer Overflow**: 4 samples (0.0%)

## Classification Enhancement Results

- **Enhanced Samples**: 0
- **Average Confidence**: nan

### Classification Changes


## Deduplication Strategy

### Exact Duplicates
- **Groups**: 959
- **Total Instances**: 2699
- **Samples to Remove**: 1740

### Semantic Duplicates
- **Similar Pairs**: 36449
- **Samples to Remove**: 36449

## High-Confidence Samples for Expert Review

Selected **1000** samples for expert validation based on:

1. Classification confidence scores
2. Code complexity (10-50 lines preferred)
3. Presence of vulnerability indicators
4. Repository diversity

### Sample Examples

#### Sample 1
- **Type**: Deserialization
- **Repository**: dCache/dcache
- **Confidence**: N/A
- **Code Lines**: 91
```java
}
         FileAttributes attributes = descriptor.getAttributes();
        AccessLatency accessLatency = attributes.getAccessLatency();
        RetentionPolicy retentionPolicy = attributes.getRetentio...
```

#### Sample 2
- **Type**: Input Validation
- **Repository**: apache/doris
- **Confidence**: N/A
- **Code Lines**: 97
```java
throw e;
             }
         }
        result.setPartitionValues(partitionValues);
         return result;
     }
                 return dummyKey.equals(((FileCacheKey) obj).dummyKey);
          ...
```

#### Sample 3
- **Type**: Access Control
- **Repository**: OpenNMS/opennms
- **Confidence**: N/A
- **Code Lines**: 34
```java
@GET
    @Path("/help")
    @Produces("text/markdown")
    public InputStream getFileHelp(@QueryParam("f") String fileName, @Context SecurityContext securityContext) {
        if (!securityContext.isU...
```

#### Sample 4
- **Type**: Race Condition
- **Repository**: lsfusion/platform
- **Confidence**: N/A
- **Code Lines**: 147
```java
}
     }
    // in theory we can also pass Thread, and then add ExecutionStackAspect.getStackString to message (to get multi thread stacj)
     @StackNewThread
     @StackMessage("NEWTHREAD")
     @Th...
```

#### Sample 5
- **Type**: Input Validation
- **Repository**: sanluan/PublicCMS
- **Confidence**: N/A
- **Code Lines**: 151
```java
@RequestMapping(params = "action=" + ACTION_CATCHIMAGE)
    @ResponseBody
    public Map<String, Object> catchimage(@RequestAttribute SysSite site, @SessionAttribute SysUser admin,
            HttpSer...
```

