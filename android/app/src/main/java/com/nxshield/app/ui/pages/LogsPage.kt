package com.nxshield.app.ui.pages

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.nxshield.app.NXAppState
import com.nxshield.engine.NxLogger
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun LogsPage(modifier: Modifier = Modifier) {
    val ctx = NXAppState.ctx()
    val logger = remember { NxLogger(ctx) }
    var history by remember { mutableStateOf<List<JSONObject>>(emptyList()) }
    var selectedId by remember { mutableStateOf<String?>(null) }
    var detail by remember { mutableStateOf<List<JSONObject>>(emptyList()) }

    fun refresh() {
        history = logger.history()
        val sel = selectedId
        if (sel != null) detail = logger.readJob(sel)
    }

    LaunchedEffect(Unit) { refresh() }

    Column(modifier = modifier.fillMaxSize().padding(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("历史日志", style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.width(12.dp))
            Button(onClick = { refresh() }) { Text("刷新") }
            Spacer(Modifier.width(8.dp))
            Button(onClick = {
                selectedId = null; detail = emptyList(); history = emptyList()
                logger.logDir.listFiles()?.forEach { it.delete() }
                refresh()
            }) { Text("清空") }
        }
        Spacer(Modifier.padding(top = 8.dp))

        LazyColumn {
            items(history, key = { it.optString("id") }) { j ->
                val id = j.optString("id")
                Card(modifier = Modifier.padding(vertical = 4.dp)) {
                    Column(Modifier.padding(12.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                j.optString("apk"),
                                style = MaterialTheme.typography.titleSmall,
                                modifier = Modifier.weight(1f),
                            )
                            Text(
                                j.optString("status"),
                                color = if (j.optString("status") == "task_done") Color(0xFF2E7D32) else Color(0xFFC62828),
                                style = MaterialTheme.typography.labelSmall,
                            )
                        }
                        Text(
                            fmt(j.optLong("start")) + " · ${j.optInt("lines")} 条",
                            style = MaterialTheme.typography.bodySmall,
                        )
                        Button(onClick = { selectedId = id; detail = logger.readJob(id) }) { Text("查看日志") }
                    }
                }
            }
        }

        if (detail.isNotEmpty()) {
            Spacer(Modifier.padding(top = 8.dp))
            Card {
                Column(Modifier.padding(12.dp)) {
                    Text("运行日志", style = MaterialTheme.typography.titleSmall)
                    detail.forEach { rec ->
                        Text(
                            recLine(rec),
                            style = MaterialTheme.typography.bodySmall,
                            color = if (rec.optString("level") == "error") Color(0xFFC62828) else MaterialTheme.colorScheme.onSurface,
                        )
                    }
                }
            }
        }
    }
}

private fun fmt(ts: Long): String =
    SimpleDateFormat("MM-dd HH:mm:ss", Locale.US).format(Date(ts))

private fun recLine(rec: JSONObject): String {
    val t = fmt(rec.optLong("ts"))
    val ev = rec.optString("event")
    val d = rec.optJSONObject("data")
    return "$t [$ev] ${d?.toString() ?: ""}"
}