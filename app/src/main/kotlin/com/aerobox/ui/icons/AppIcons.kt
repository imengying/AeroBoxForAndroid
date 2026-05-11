package com.aerobox.ui.icons

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathFillType
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.path
import androidx.compose.ui.unit.dp

/**
 * Lightweight custom icon definitions to avoid pulling in
 * the entire material-icons-extended library (~10+ MB).
 */
object AppIcons {

    val ContentCopy: ImageVector by lazy {
        ImageVector.Builder("ContentCopy", 24.dp, 24.dp, 24f, 24f).apply {
            path(fill = SolidColor(Color.Black)) {
                moveTo(16f, 1f)
                horizontalLineTo(4f)
                curveTo(2.9f, 1f, 2f, 1.9f, 2f, 3f)
                verticalLineToRelative(14f)
                horizontalLineToRelative(2f)
                verticalLineTo(3f)
                horizontalLineToRelative(12f)
                verticalLineTo(1f)
                close()

                moveTo(19f, 5f)
                horizontalLineTo(8f)
                curveTo(6.9f, 5f, 6f, 5.9f, 6f, 7f)
                verticalLineToRelative(14f)
                curveToRelative(0f, 1.1f, 0.9f, 2f, 2f, 2f)
                horizontalLineToRelative(11f)
                curveToRelative(1.1f, 0f, 2f, -0.9f, 2f, -2f)
                verticalLineTo(7f)
                curveToRelative(0f, -1.1f, -0.9f, -2f, -2f, -2f)
                close()

                moveTo(19f, 21f)
                horizontalLineTo(8f)
                verticalLineTo(7f)
                horizontalLineToRelative(11f)
                verticalLineToRelative(14f)
                close()
            }
        }.build()
    }

    val ColorLens: ImageVector by lazy {
        ImageVector.Builder("ColorLens", 24.dp, 24.dp, 24f, 24f).apply {
            path(fill = SolidColor(Color.Black), pathFillType = PathFillType.EvenOdd) {
                moveTo(12f, 3f)
                curveTo(7.03f, 3f, 3f, 7.03f, 3f, 12f)
                reflectiveCurveToRelative(4.03f, 9f, 9f, 9f)
                curveToRelative(0.83f, 0f, 1.5f, -0.67f, 1.5f, -1.5f)
                curveToRelative(0f, -0.39f, -0.15f, -0.74f, -0.39f, -1.01f)
                curveToRelative(-0.23f, -0.26f, -0.38f, -0.61f, -0.38f, -0.99f)
                curveToRelative(0f, -0.83f, 0.67f, -1.5f, 1.5f, -1.5f)
                horizontalLineTo(16f)
                curveToRelative(2.76f, 0f, 5f, -2.24f, 5f, -5f)
                curveToRelative(0f, -4.42f, -4.03f, -8f, -9f, -8f)
                close()
                moveTo(6.5f, 12f)
                curveToRelative(-0.83f, 0f, -1.5f, -0.67f, -1.5f, -1.5f)
                reflectiveCurveTo(5.67f, 9f, 6.5f, 9f)
                reflectiveCurveTo(8f, 9.67f, 8f, 10.5f)
                reflectiveCurveTo(7.33f, 12f, 6.5f, 12f)
                close()
                moveTo(9.5f, 8f)
                curveTo(8.67f, 8f, 8f, 7.33f, 8f, 6.5f)
                reflectiveCurveTo(8.67f, 5f, 9.5f, 5f)
                reflectiveCurveTo(11f, 5.67f, 11f, 6.5f)
                reflectiveCurveTo(10.33f, 8f, 9.5f, 8f)
                close()
                moveTo(14.5f, 8f)
                curveToRelative(-0.83f, 0f, -1.5f, -0.67f, -1.5f, -1.5f)
                reflectiveCurveTo(13.67f, 5f, 14.5f, 5f)
                reflectiveCurveTo(16f, 5.67f, 16f, 6.5f)
                reflectiveCurveTo(15.33f, 8f, 14.5f, 8f)
                close()
                moveTo(17.5f, 12f)
                curveToRelative(-0.83f, 0f, -1.5f, -0.67f, -1.5f, -1.5f)
                reflectiveCurveTo(16.67f, 9f, 17.5f, 9f)
                reflectiveCurveTo(19f, 9.67f, 19f, 10.5f)
                reflectiveCurveTo(18.33f, 12f, 17.5f, 12f)
                close()
            }
        }.build()
    }

    val DarkMode: ImageVector by lazy {
        ImageVector.Builder("DarkMode", 24.dp, 24.dp, 24f, 24f).apply {
            path(fill = SolidColor(Color.Black)) {
                moveTo(12f, 3f)
                curveToRelative(-4.97f, 0f, -9f, 4.03f, -9f, 9f)
                reflectiveCurveToRelative(4.03f, 9f, 9f, 9f)
                reflectiveCurveToRelative(9f, -4.03f, 9f, -9f)
                curveToRelative(0f, -0.46f, -0.04f, -0.92f, -0.1f, -1.36f)
                curveToRelative(-0.98f, 1.37f, -2.58f, 2.26f, -4.4f, 2.26f)
                curveToRelative(-2.98f, 0f, -5.4f, -2.42f, -5.4f, -5.4f)
                curveToRelative(0f, -1.81f, 0.89f, -3.42f, 2.26f, -4.4f)
                curveTo(12.92f, 3.04f, 12.46f, 3f, 12f, 3f)
                close()
            }
        }.build()
    }

    val Power: ImageVector by lazy {
        ImageVector.Builder("Power", 24.dp, 24.dp, 24f, 24f).apply {
            path(fill = SolidColor(Color.Black)) {
                moveTo(13f, 3f)
                horizontalLineToRelative(-2f)
                verticalLineToRelative(10f)
                horizontalLineToRelative(2f)
                verticalLineTo(3f)
                close()
                moveTo(17.83f, 5.17f)
                lineToRelative(-1.42f, 1.42f)
                curveTo(17.99f, 7.86f, 19f, 9.81f, 19f, 12f)
                curveToRelative(0f, 3.87f, -3.13f, 7f, -7f, 7f)
                reflectiveCurveToRelative(-7f, -3.13f, -7f, -7f)
                curveToRelative(0f, -2.19f, 1.01f, -4.14f, 2.58f, -5.42f)
                lineTo(6.17f, 5.17f)
                curveTo(4.23f, 6.82f, 3f, 9.26f, 3f, 12f)
                curveToRelative(0f, 4.97f, 4.03f, 9f, 9f, 9f)
                reflectiveCurveToRelative(9f, -4.03f, 9f, -9f)
                curveToRelative(0f, -2.74f, -1.23f, -5.18f, -3.17f, -6.83f)
                close()
            }
        }.build()
    }

    val Security: ImageVector by lazy {
        ImageVector.Builder("Security", 24.dp, 24.dp, 24f, 24f).apply {
            path(fill = SolidColor(Color.Black)) {
                moveTo(12f, 1f)
                lineTo(3f, 5f)
                verticalLineToRelative(6f)
                curveToRelative(0f, 5.55f, 3.84f, 10.74f, 9f, 12f)
                curveToRelative(5.16f, -1.26f, 9f, -6.45f, 9f, -12f)
                verticalLineTo(5f)
                lineToRelative(-9f, -4f)
                close()
                moveTo(12f, 11.99f)
                horizontalLineToRelative(7f)
                curveToRelative(-0.53f, 4.12f, -3.28f, 7.79f, -7f, 8.94f)
                verticalLineTo(12f)
                horizontalLineTo(5f)
                verticalLineTo(6.3f)
                lineToRelative(7f, -3.11f)
                verticalLineToRelative(8.8f)
                close()
            }
        }.build()
    }

    val Speed: ImageVector by lazy {
        ImageVector.Builder("Speed", 24.dp, 24.dp, 24f, 24f).apply {
            path(fill = SolidColor(Color.Black)) {
                moveTo(20.38f, 8.57f)
                lineToRelative(-1.23f, 1.85f)
                curveToRelative(0.53f, 0.97f, 0.85f, 2.06f, 0.85f, 3.23f)
                curveToRelative(0f, 3.7f, -3.01f, 6.7f, -6.71f, 6.7f)
                reflectiveCurveToRelative(-6.71f, -3f, -6.71f, -6.7f)
                curveToRelative(0f, -3.7f, 3.01f, -6.7f, 6.71f, -6.7f)
                curveToRelative(0.76f, 0f, 1.49f, 0.13f, 2.17f, 0.36f)
                lineToRelative(1.84f, -1.23f)
                curveTo(16.01f, 5.43f, 14.57f, 5f, 13.04f, 5f)
                horizontalLineToRelative(-0.18f)
                lineToRelative(1.01f, -3f)
                lineToRelative(-2.04f, 0f)
                lineToRelative(-1.01f, 3f)
                lineToRelative(-0.86f, 0f)
                curveTo(5.55f, 5f, 2f, 8.58f, 2f, 13.65f)
                curveToRelative(0f, 4.59f, 3.37f, 8.35f, 8f, 8.35f)
                reflectiveCurveToRelative(8f, -3.76f, 8f, -8.35f)
                curveToRelative(0f, -1.88f, -0.59f, -3.62f, -1.62f, -5.08f)
                close()
                moveTo(10.59f, 15.41f)
                curveToRelative(0.78f, 0.78f, 2.05f, 0.78f, 2.83f, 0f)
                lineToRelative(5.66f, -8.49f)
                lineToRelative(-8.49f, 5.66f)
                curveToRelative(-0.78f, 0.78f, -0.78f, 2.05f, 0f, 2.83f)
                close()
            }
        }.build()
    }

    val Flight: ImageVector by lazy {
        ImageVector.Builder("Flight", 24.dp, 24.dp, 24f, 24f).apply {
            path(fill = SolidColor(Color.Black)) {
                moveTo(21f, 16f)
                verticalLineToRelative(-2f)
                lineToRelative(-8f, -5f)
                verticalLineTo(3.5f)
                curveToRelative(0f, -0.83f, -0.67f, -1.5f, -1.5f, -1.5f)
                reflectiveCurveTo(10f, 2.67f, 10f, 3.5f)
                verticalLineTo(9f)
                lineToRelative(-8f, 5f)
                verticalLineToRelative(2f)
                lineToRelative(8f, -2.5f)
                verticalLineTo(19f)
                lineToRelative(-2f, 1.5f)
                verticalLineTo(22f)
                lineToRelative(3.5f, -1f)
                lineToRelative(3.5f, 1f)
                verticalLineToRelative(-1.5f)
                lineTo(13f, 19f)
                verticalLineToRelative(-5.5f)
                lineTo(21f, 16f)
                close()
            }
        }.build()
    }

    val Translate: ImageVector by lazy {
        ImageVector.Builder("Translate", 24.dp, 24.dp, 24f, 24f).apply {
            path(fill = SolidColor(Color.Black)) {
                moveTo(12.87f, 15.07f)
                lineToRelative(-2.54f, -2.51f)
                lineToRelative(0.03f, -0.03f)
                curveToRelative(1.74f, -1.94f, 2.98f, -4.17f, 3.71f, -6.53f)
                horizontalLineTo(17f)
                verticalLineTo(4f)
                horizontalLineToRelative(-7f)
                verticalLineTo(2f)
                horizontalLineTo(8f)
                verticalLineToRelative(2f)
                horizontalLineTo(1f)
                verticalLineToRelative(1.99f)
                horizontalLineToRelative(11.17f)
                curveTo(11.5f, 7.92f, 10.44f, 9.75f, 9f, 11.35f)
                curveTo(8.07f, 10.32f, 7.3f, 9.19f, 6.69f, 8f)
                horizontalLineTo(4.69f)
                curveToRelative(0.73f, 1.63f, 1.73f, 3.17f, 2.98f, 4.56f)
                lineToRelative(-5.09f, 5.02f)
                lineTo(4f, 19f)
                lineToRelative(5f, -5f)
                lineToRelative(3.11f, 3.11f)
                lineToRelative(0.76f, -2.04f)
                close()
                moveTo(18.5f, 10f)
                horizontalLineToRelative(-2f)
                lineTo(12f, 22f)
                horizontalLineToRelative(2f)
                lineToRelative(1.12f, -3f)
                horizontalLineToRelative(4.75f)
                lineTo(21f, 22f)
                horizontalLineToRelative(2f)
                lineToRelative(-4.5f, -12f)
                close()
                moveTo(15.88f, 17f)
                lineToRelative(1.62f, -4.33f)
                lineTo(19.12f, 17f)
                horizontalLineToRelative(-3.24f)
                close()
            }
        }.build()
    }

    val Apps: ImageVector by lazy {
        ImageVector.Builder("Apps", 24.dp, 24.dp, 24f, 24f).apply {
            path(fill = SolidColor(Color.Black)) {
                moveTo(4f, 8f)
                horizontalLineToRelative(4f)
                verticalLineTo(4f)
                horizontalLineTo(4f)
                verticalLineToRelative(4f)
                close()
                moveTo(10f, 20f)
                horizontalLineToRelative(4f)
                verticalLineToRelative(-4f)
                horizontalLineToRelative(-4f)
                verticalLineToRelative(4f)
                close()
                moveTo(4f, 20f)
                horizontalLineToRelative(4f)
                verticalLineToRelative(-4f)
                horizontalLineTo(4f)
                verticalLineToRelative(4f)
                close()
                moveTo(4f, 14f)
                horizontalLineToRelative(4f)
                verticalLineToRelative(-4f)
                horizontalLineTo(4f)
                verticalLineToRelative(4f)
                close()
                moveTo(10f, 14f)
                horizontalLineToRelative(4f)
                verticalLineToRelative(-4f)
                horizontalLineToRelative(-4f)
                verticalLineToRelative(4f)
                close()
                moveTo(16f, 4f)
                verticalLineToRelative(4f)
                horizontalLineToRelative(4f)
                verticalLineTo(4f)
                horizontalLineToRelative(-4f)
                close()
                moveTo(16f, 14f)
                horizontalLineToRelative(4f)
                verticalLineToRelative(-4f)
                horizontalLineToRelative(-4f)
                verticalLineToRelative(4f)
                close()
                moveTo(16f, 20f)
                horizontalLineToRelative(4f)
                verticalLineToRelative(-4f)
                horizontalLineToRelative(-4f)
                verticalLineToRelative(4f)
                close()
                moveTo(10f, 8f)
                horizontalLineToRelative(4f)
                verticalLineTo(4f)
                horizontalLineToRelative(-4f)
                verticalLineToRelative(4f)
                close()
            }
        }.build()
    }

    val Route: ImageVector by lazy {
        ImageVector.Builder("Route", 24.dp, 24.dp, 24f, 24f).apply {
            path(fill = SolidColor(Color.Black)) {
                moveTo(19f, 15.18f)
                verticalLineTo(7f)
                curveToRelative(0f, -2.21f, -1.79f, -4f, -4f, -4f)
                reflectiveCurveToRelative(-4f, 1.79f, -4f, 4f)
                verticalLineToRelative(10f)
                curveToRelative(0f, 1.1f, -0.9f, 2f, -2f, 2f)
                reflectiveCurveToRelative(-2f, -0.9f, -2f, -2f)
                verticalLineTo(8.82f)
                curveTo(8.16f, 8.4f, 9f, 7.3f, 9f, 6f)
                curveToRelative(0f, -1.66f, -1.34f, -3f, -3f, -3f)
                reflectiveCurveTo(3f, 4.34f, 3f, 6f)
                curveToRelative(0f, 1.3f, 0.84f, 2.4f, 2f, 2.82f)
                verticalLineTo(17f)
                curveToRelative(0f, 2.21f, 1.79f, 4f, 4f, 4f)
                reflectiveCurveToRelative(4f, -1.79f, 4f, -4f)
                verticalLineTo(7f)
                curveToRelative(0f, -1.1f, 0.9f, -2f, 2f, -2f)
                reflectiveCurveToRelative(2f, 0.9f, 2f, 2f)
                verticalLineToRelative(8.18f)
                curveToRelative(-1.16f, 0.41f, -2f, 1.51f, -2f, 2.82f)
                curveToRelative(0f, 1.66f, 1.34f, 3f, 3f, 3f)
                reflectiveCurveToRelative(3f, -1.34f, 3f, -3f)
                curveTo(21f, 16.7f, 20.16f, 15.6f, 19f, 15.18f)
                close()
            }
        }.build()
    }

    val Dns: ImageVector by lazy {
        ImageVector.Builder("Dns", 24.dp, 24.dp, 24f, 24f).apply {
            path(fill = SolidColor(Color.Black)) {
                moveTo(20f, 13f)
                horizontalLineTo(4f)
                curveToRelative(-0.55f, 0f, -1f, 0.45f, -1f, 1f)
                verticalLineToRelative(6f)
                curveToRelative(0f, 0.55f, 0.45f, 1f, 1f, 1f)
                horizontalLineToRelative(16f)
                curveToRelative(0.55f, 0f, 1f, -0.45f, 1f, -1f)
                verticalLineToRelative(-6f)
                curveTo(21f, 13.45f, 20.55f, 13f, 20f, 13f)
                close()
                moveTo(7f, 19f)
                curveToRelative(-1.1f, 0f, -2f, -0.9f, -2f, -2f)
                reflectiveCurveToRelative(0.9f, -2f, 2f, -2f)
                reflectiveCurveToRelative(2f, 0.9f, 2f, 2f)
                reflectiveCurveTo(8.1f, 19f, 7f, 19f)
                close()
                moveTo(20f, 3f)
                horizontalLineTo(4f)
                curveTo(3.45f, 3f, 3f, 3.45f, 3f, 4f)
                verticalLineToRelative(6f)
                curveToRelative(0f, 0.55f, 0.45f, 1f, 1f, 1f)
                horizontalLineToRelative(16f)
                curveToRelative(0.55f, 0f, 1f, -0.45f, 1f, -1f)
                verticalLineTo(4f)
                curveTo(21f, 3.45f, 20.55f, 3f, 20f, 3f)
                close()
                moveTo(7f, 9f)
                curveTo(5.9f, 9f, 5f, 8.1f, 5f, 7f)
                reflectiveCurveToRelative(0.9f, -2f, 2f, -2f)
                reflectiveCurveToRelative(2f, 0.9f, 2f, 2f)
                reflectiveCurveTo(8.1f, 9f, 7f, 9f)
                close()
            }
        }.build()
    }

    val Public: ImageVector by lazy {
        ImageVector.Builder("Public", 24.dp, 24.dp, 24f, 24f).apply {
            path(fill = SolidColor(Color.Black)) {
                moveTo(12f, 2f)
                curveTo(6.48f, 2f, 2f, 6.48f, 2f, 12f)
                reflectiveCurveToRelative(4.48f, 10f, 10f, 10f)
                reflectiveCurveToRelative(10f, -4.48f, 10f, -10f)
                reflectiveCurveTo(17.52f, 2f, 12f, 2f)
                close()
                moveTo(11f, 19.93f)
                curveToRelative(-3.95f, -0.49f, -7f, -3.85f, -7f, -7.93f)
                curveToRelative(0f, -0.62f, 0.08f, -1.21f, 0.21f, -1.79f)
                lineTo(9f, 15f)
                verticalLineToRelative(1f)
                curveToRelative(0f, 1.1f, 0.9f, 2f, 2f, 2f)
                verticalLineTo(19.93f)
                close()
                moveTo(17.9f, 17.39f)
                curveToRelative(-0.26f, -0.81f, -1f, -1.39f, -1.9f, -1.39f)
                horizontalLineToRelative(-1f)
                verticalLineToRelative(-3f)
                curveToRelative(0f, -0.55f, -0.45f, -1f, -1f, -1f)
                horizontalLineTo(8f)
                verticalLineToRelative(-2f)
                horizontalLineToRelative(2f)
                curveToRelative(0.55f, 0f, 1f, -0.45f, 1f, -1f)
                verticalLineTo(7f)
                horizontalLineToRelative(2f)
                curveToRelative(1.1f, 0f, 2f, -0.9f, 2f, -2f)
                verticalLineToRelative(-0.41f)
                curveToRelative(2.93f, 1.19f, 5f, 4.06f, 5f, 7.41f)
                curveTo(20f, 14.08f, 19.22f, 15.93f, 17.9f, 17.39f)
                close()
            }
        }.build()
    }

    val Input: ImageVector by lazy {
        ImageVector.Builder("Input", 24.dp, 24.dp, 24f, 24f).apply {
            path(fill = SolidColor(Color.Black)) {
                moveTo(21f, 3.01f)
                horizontalLineTo(3f)
                curveToRelative(-1.1f, 0f, -2f, 0.9f, -2f, 2f)
                verticalLineTo(9f)
                horizontalLineToRelative(2f)
                verticalLineTo(4.99f)
                horizontalLineToRelative(18f)
                verticalLineToRelative(14.03f)
                horizontalLineTo(3f)
                verticalLineTo(15f)
                horizontalLineTo(1f)
                verticalLineToRelative(4.01f)
                curveToRelative(0f, 1.1f, 0.9f, 1.98f, 2f, 1.98f)
                horizontalLineToRelative(18f)
                curveToRelative(1.1f, 0f, 2f, -0.88f, 2f, -1.98f)
                verticalLineToRelative(-14f)
                curveTo(23f, 3.9f, 22.1f, 3.01f, 21f, 3.01f)
                close()
                moveTo(11f, 16f)
                lineToRelative(4f, -4f)
                lineToRelative(-4f, -4f)
                verticalLineToRelative(3f)
                horizontalLineTo(1f)
                verticalLineToRelative(2f)
                horizontalLineToRelative(10f)
                verticalLineTo(16f)
                close()
            }
        }.build()
    }

    val Autorenew: ImageVector by lazy {
        ImageVector.Builder("Autorenew", 24.dp, 24.dp, 24f, 24f).apply {
            path(fill = SolidColor(Color.Black)) {
                moveTo(12f, 6f)
                verticalLineToRelative(3f)
                lineToRelative(4f, -4f)
                lineToRelative(-4f, -4f)
                verticalLineToRelative(3f)
                curveToRelative(-4.42f, 0f, -8f, 3.58f, -8f, 8f)
                curveToRelative(0f, 1.57f, 0.46f, 3.03f, 1.24f, 4.26f)
                lineTo(6.7f, 14.8f)
                curveTo(6.25f, 13.97f, 6f, 13.01f, 6f, 12f)
                curveTo(6f, 8.69f, 8.69f, 6f, 12f, 6f)
                close()
                moveTo(18.76f, 7.74f)
                lineTo(17.3f, 9.2f)
                curveTo(17.75f, 10.03f, 18f, 10.99f, 18f, 12f)
                curveToRelative(0f, 3.31f, -2.69f, 6f, -6f, 6f)
                verticalLineToRelative(-3f)
                lineToRelative(-4f, 4f)
                lineToRelative(4f, 4f)
                verticalLineToRelative(-3f)
                curveToRelative(4.42f, 0f, 8f, -3.58f, 8f, -8f)
                curveTo(20f, 10.43f, 19.54f, 8.97f, 18.76f, 7.74f)
                close()
            }
        }.build()
    }

    val Description: ImageVector by lazy {
        ImageVector.Builder("Description", 24.dp, 24.dp, 24f, 24f).apply {
            path(fill = SolidColor(Color.Black)) {
                moveTo(14f, 2f)
                horizontalLineTo(6f)
                curveTo(4.9f, 2f, 4f, 2.9f, 4f, 4f)
                verticalLineToRelative(16f)
                curveToRelative(0f, 1.1f, 0.89f, 2f, 1.99f, 2f)
                horizontalLineTo(18f)
                curveToRelative(1.1f, 0f, 2f, -0.9f, 2f, -2f)
                verticalLineTo(8f)
                lineTo(14f, 2f)
                close()
                moveTo(16f, 18f)
                horizontalLineTo(8f)
                verticalLineToRelative(-2f)
                horizontalLineToRelative(8f)
                verticalLineTo(18f)
                close()
                moveTo(16f, 14f)
                horizontalLineTo(8f)
                verticalLineToRelative(-2f)
                horizontalLineToRelative(8f)
                verticalLineTo(14f)
                close()
                moveTo(13f, 9f)
                verticalLineTo(3.5f)
                lineTo(18.5f, 9f)
                horizontalLineTo(13f)
                close()
            }
        }.build()
    }

    val Add: ImageVector by lazy {
        ImageVector.Builder("Add", 24.dp, 24.dp, 24f, 24f).apply {
            path(fill = SolidColor(Color.Black)) {
                moveTo(19f, 13f)
                horizontalLineToRelative(-6f)
                verticalLineToRelative(6f)
                horizontalLineToRelative(-2f)
                verticalLineToRelative(-6f)
                horizontalLineTo(5f)
                verticalLineToRelative(-2f)
                horizontalLineToRelative(6f)
                verticalLineTo(5f)
                horizontalLineToRelative(2f)
                verticalLineToRelative(6f)
                horizontalLineToRelative(6f)
                verticalLineToRelative(2f)
                close()
            }
        }.build()
    }
}
