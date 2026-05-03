package com.aerobox.ui.scanner

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.RectF
import android.util.AttributeSet
import com.aerobox.R
import com.journeyapps.barcodescanner.ViewfinderView

class AeroBoxQrViewfinderView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null
) : ViewfinderView(context, attrs) {
    private val density = resources.displayMetrics.density
    private val frameRadius = 20f * density
    private val cornerLength = 24f * density
    private val frameStrokeWidth = 2f * density
    private val cornerStrokeWidth = 4f * density

    private val framePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = context.getColor(R.color.qr_scanner_frame)
        style = Paint.Style.STROKE
        strokeWidth = frameStrokeWidth
    }

    private val cornerPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = context.getColor(R.color.qr_scanner_corner)
        style = Paint.Style.STROKE
        strokeWidth = cornerStrokeWidth
        strokeCap = Paint.Cap.ROUND
    }

    override fun onDraw(canvas: Canvas) {
        refreshSizes()
        val frame = framingRect ?: return
        val preview = previewSize ?: return

        val width = width.toFloat()
        val height = height.toFloat()

        paint.color = if (resultBitmap != null) resultColor else maskColor
        canvas.drawRect(0f, 0f, width, frame.top.toFloat(), paint)
        canvas.drawRect(0f, frame.top.toFloat(), frame.left.toFloat(), frame.bottom.toFloat() + 1f, paint)
        canvas.drawRect(frame.right.toFloat() + 1f, frame.top.toFloat(), width, frame.bottom.toFloat() + 1f, paint)
        canvas.drawRect(0f, frame.bottom.toFloat() + 1f, width, height, paint)

        resultBitmap?.let { bitmap ->
            paint.alpha = CURRENT_POINT_OPACITY
            canvas.drawBitmap(bitmap, null, frame, paint)
            return
        }

        val rect = RectF(frame)
        canvas.drawRoundRect(rect, frameRadius, frameRadius, framePaint)
        drawCornerAccents(canvas, rect)

        val scaleX = this.width / preview.width.toFloat()
        val scaleY = this.height / preview.height.toFloat()

        if (lastPossibleResultPoints.isNotEmpty()) {
            paint.alpha = CURRENT_POINT_OPACITY / 2
            paint.color = resultPointColor
            val radius = POINT_SIZE / 2f
            for (point in lastPossibleResultPoints) {
                canvas.drawCircle(point.x * scaleX, point.y * scaleY, radius, paint)
            }
            lastPossibleResultPoints.clear()
        }

        if (possibleResultPoints.isNotEmpty()) {
            paint.alpha = CURRENT_POINT_OPACITY
            paint.color = resultPointColor
            for (point in possibleResultPoints) {
                canvas.drawCircle(point.x * scaleX, point.y * scaleY, POINT_SIZE.toFloat(), paint)
            }
            val temp = possibleResultPoints
            possibleResultPoints = lastPossibleResultPoints
            lastPossibleResultPoints = temp
            possibleResultPoints.clear()
        }

        postInvalidateDelayed(
            ANIMATION_DELAY,
            frame.left - POINT_SIZE,
            frame.top - POINT_SIZE,
            frame.right + POINT_SIZE,
            frame.bottom + POINT_SIZE
        )
    }

    private fun drawCornerAccents(canvas: Canvas, rect: RectF) {
        val left = rect.left
        val top = rect.top
        val right = rect.right
        val bottom = rect.bottom

        canvas.drawLine(left, top + cornerLength, left, top, cornerPaint)
        canvas.drawLine(left, top, left + cornerLength, top, cornerPaint)

        canvas.drawLine(right - cornerLength, top, right, top, cornerPaint)
        canvas.drawLine(right, top, right, top + cornerLength, cornerPaint)

        canvas.drawLine(left, bottom - cornerLength, left, bottom, cornerPaint)
        canvas.drawLine(left, bottom, left + cornerLength, bottom, cornerPaint)

        canvas.drawLine(right - cornerLength, bottom, right, bottom, cornerPaint)
        canvas.drawLine(right, bottom - cornerLength, right, bottom, cornerPaint)
    }
}
